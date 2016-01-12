/***
Copyright 2014 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package ofnet

// This file implements ofnet agent API which runs on each host alongside OVS.
// This assumes:
//      - ofnet agent is running on each host
//      - There is single OVS switch instance(aka bridge instance)
//      - OVS switch's forwarding is fully controller by ofnet agent
//
// It also assumes OVS is configured for openflow1.3 version and configured
// to connect to controller on specified port

import (
	"errors"
	"fmt"
	"github.com/contiv/ofnet/ofctrl"
	"github.com/contiv/ofnet/ovsdbDriver"
	"github.com/contiv/ofnet/rpcHub"
	"io"
	"net"
	"net/rpc"
	"os/exec"
	"strconv"
	"time"

	log "github.com/Sirupsen/logrus"
	api "github.com/osrg/gobgp/api"
	bgpconf "github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	bgpserver "github.com/osrg/gobgp/server"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

// OfnetAgent state
type OfnetAgent struct {
	ctrler      *ofctrl.Controller // Controller instance
	ofSwitch    *ofctrl.OFSwitch   // Switch instance. Assumes single switch per agent
	localIp     net.IP             // Local IP to be used for tunnel end points
	MyPort      uint16             // Port where the agent's RPC server is listening
	MyAddr      string             // RPC server addr. same as localIp. different in testing environments
	isConnected bool               // Is the switch connected
	routerIP    string             // virtual interface ip for bgp
	rpcServ     *rpc.Server        // jsonrpc server
	rpcListener net.Listener       // Listener
	datapath    OfnetDatapath      // Configured datapath
	vlanIntf    string             // uplink port name

	masterDb map[string]*OfnetNode // list of Masters

	// Port and VNI to vlan mapping table
	portVlanMap map[uint32]*uint16 // Map port number to vlan
	vniVlanMap  map[uint32]*uint16 // Map VNI to vlan
	vlanVniMap  map[uint16]*uint32 // Map vlan to VNI

	// VTEP database
	vtepTable map[string]*uint32 // Map vtep IP to OVS port number

	// Endpoint database
	endpointDb      map[string]*OfnetEndpoint // all known endpoints
	localEndpointDb map[uint32]*OfnetEndpoint // local port to endpoint map

	//bgp resources
	modRibCh   chan *api.Path //channel for route change notif
	advPathCh  chan *api.Path
	bgpServer  *bgpserver.BgpServer // bgp server instance
	grpcServer *bgpserver.Server    // grpc server to talk to gobgp
	myBgpPeer  string               // bgp peer ip

	ovsDriver *ovsdbDriver.OvsDriver
}

// local End point information
type EndpointInfo struct {
	PortNo        uint32
	EndpointGroup int
	MacAddr       net.HardwareAddr
	Vlan          uint16
	IpAddr        net.IP
	VrfId         uint16
}

const FLOW_MATCH_PRIORITY = 100        // Priority for all match flows
const FLOW_FLOOD_PRIORITY = 10         // Priority for flood entries
const FLOW_MISS_PRIORITY = 1           // priority for table miss flow
const FLOW_POLICY_PRIORITY_OFFSET = 10 // Priority offset for policy rules

const VLAN_TBL_ID = 1
const DST_GRP_TBL_ID = 2
const POLICY_TBL_ID = 3
const IP_TBL_ID = 4
const MAC_DEST_TBL_ID = 5

// Create a new Ofnet agent and initialize it
/*routerInfo[0] - > IP of the router intf
  routerInfo[1] -> Uplink nexthop interface
*/
func NewOfnetAgent(dpName string, localIp net.IP, rpcPort uint16, ovsPort uint16, routerInfo ...string) (*OfnetAgent, error) {
	agent := new(OfnetAgent)

	// Init params
	agent.localIp = localIp
	agent.MyPort = rpcPort
	agent.MyAddr = localIp.String()
	if len(routerInfo) > 1 {
		//Ensuring routerInfo is in ip format
		if ok := net.ParseIP(routerInfo[0]); ok != nil {
			agent.routerIP = routerInfo[0]
		} else {
			log.Errorf("Error creating OfnetAgent")
			return nil, errors.New("Error parsing IP")
		}
		agent.vlanIntf = routerInfo[1]
	}

	agent.masterDb = make(map[string]*OfnetNode)
	agent.portVlanMap = make(map[uint32]*uint16)
	agent.vniVlanMap = make(map[uint32]*uint16)
	agent.vlanVniMap = make(map[uint16]*uint32)

	// Initialize vtep database
	agent.vtepTable = make(map[string]*uint32)

	// Initialize endpoint database
	agent.endpointDb = make(map[string]*OfnetEndpoint)
	agent.localEndpointDb = make(map[uint32]*OfnetEndpoint)

	// Create an openflow controller
	agent.ctrler = ofctrl.NewController(agent)

	// Start listening to controller port
	go agent.ctrler.Listen(fmt.Sprintf(":%d", ovsPort))

	// Create rpc server
	// FIXME: Figure out how to handle multiple OVS bridges.
	rpcServ, listener := rpcHub.NewRpcServer(rpcPort)
	agent.rpcServ = rpcServ
	agent.rpcListener = listener

	// Register for Master add/remove events
	rpcServ.Register(agent)

	// Create the datapath
	switch dpName {
	case "vrouter":
		agent.datapath = NewVrouter(agent, rpcServ)
	case "vxlan":
		agent.datapath = NewVxlan(agent, rpcServ)
	case "vlan":
		agent.datapath = NewVlanBridge(agent, rpcServ)
	case "vlrouter":
		agent.datapath = NewVlrouter(agent, rpcServ)
		agent.ovsDriver = ovsdbDriver.NewOvsDriver("contivVlanBridge")
		agent.bgpServer, agent.grpcServer = CreateBgpServer()
		//go routine to start gobgp server
		go func() {
			err := agent.Serve()
			if err != nil {
				log.Errorf("protocol server finished with err: %s", err)
			}
		}()

	default:
		log.Fatalf("Unknown Datapath %s", dpName)
	}

	// Return it
	return agent, nil
}

// getEndpointId Get a unique identifier for the endpoint.
// FIXME: This needs to be VRF, IP address.
func (self *OfnetAgent) getEndpointId(endpoint EndpointInfo) string {
	return endpoint.IpAddr.String()
}

func (self *OfnetAgent) getEndpointByIp(ipAddr net.IP) *OfnetEndpoint {
	return self.endpointDb[ipAddr.String()]
}

// Delete cleans up an ofnet agent
func (self *OfnetAgent) Delete() error {
	// Disconnect from the switch
	if self.ofSwitch != nil {
		self.ofSwitch.Disconnect()
	}

	// Cleanup the controller
	self.ctrler.Delete()

	// close listeners
	self.rpcListener.Close()

	time.Sleep(100 * time.Millisecond)

	return nil
}

// Handle switch connected event
func (self *OfnetAgent) SwitchConnected(sw *ofctrl.OFSwitch) {
	log.Infof("Switch %v connected", sw.DPID())

	// store it for future use.
	self.ofSwitch = sw

	// Inform the datapath
	self.datapath.SwitchConnected(sw)

	self.isConnected = true
}

// Handle switch disconnect event
func (self *OfnetAgent) SwitchDisconnected(sw *ofctrl.OFSwitch) {
	log.Infof("Switch %v disconnected", sw.DPID())

	// Inform the datapath
	self.datapath.SwitchDisconnected(sw)

	self.ofSwitch = nil
	self.isConnected = false
}

// IsSwitchConnected returns true if switch is connected
func (self *OfnetAgent) IsSwitchConnected() bool {
	return self.isConnected
}

// WaitForSwitchConnection wait till switch connects
func (self *OfnetAgent) WaitForSwitchConnection() {
	// Wait for a while for OVS switch to connect to ofnet agent
	for i := 0; i < 20; i++ {
		time.Sleep(1 * time.Second)
		if self.IsSwitchConnected() {
			break
		}
	}
}

// Receive a packet from the switch.
func (self *OfnetAgent) PacketRcvd(sw *ofctrl.OFSwitch, pkt *ofctrl.PacketIn) {
	log.Infof("Packet received from switch %v. Packet: %+v", sw.DPID(), pkt)
	log.Infof("Input Port: %+v", pkt.Match.Fields[0].Value)

	// Inform the datapath
	self.datapath.PacketRcvd(sw, pkt)
}

// Add a master
// ofnet agent tries to connect to the master and download routes
func (self *OfnetAgent) AddMaster(masterInfo *OfnetNode, ret *bool) error {
	master := new(OfnetNode)
	master.HostAddr = masterInfo.HostAddr
	master.HostPort = masterInfo.HostPort

	var resp bool

	log.Infof("Adding master: %+v", *master)

	masterKey := fmt.Sprintf("%s:%d", masterInfo.HostAddr, masterInfo.HostPort)

	// Save it in DB
	self.masterDb[masterKey] = master

	// My info to send to master
	myInfo := new(OfnetNode)
	myInfo.HostAddr = self.MyAddr
	myInfo.HostPort = self.MyPort

	// Register the agent with the master
	err := rpcHub.Client(master.HostAddr, master.HostPort).Call("OfnetMaster.RegisterNode", &myInfo, &resp)
	if err != nil {
		log.Errorf("Failed to register with the master %+v. Err: %v", master, err)
		return err
	}

	// Perform master added callback so that datapaths can send their FDB to master
	err = self.datapath.MasterAdded(master)
	if err != nil {
		log.Errorf("Error making master added callback for %+v. Err: %v", master, err)
	}

	// Send all local endpoints to new master.
	for _, endpoint := range self.localEndpointDb {
		if endpoint.OriginatorIp.String() == self.localIp.String() {
			var resp bool

			log.Infof("Sending endpoint %+v to master %+v", endpoint, master)

			// Make the RPC call to add the endpoint to master
			client := rpcHub.Client(master.HostAddr, master.HostPort)
			err := client.Call("OfnetMaster.EndpointAdd", endpoint, &resp)
			if err != nil {
				log.Errorf("Failed to add endpoint %+v to master %+v. Err: %v", endpoint, master, err)
				return err
			}
		}
	}

	return nil
}

// Remove the master from master DB
func (self *OfnetAgent) RemoveMaster(masterInfo *OfnetNode) error {
	log.Infof("Deleting master: %+v", masterInfo)

	masterKey := fmt.Sprintf("%s:%d", masterInfo.HostAddr, masterInfo.HostPort)

	// Remove it from DB
	delete(self.masterDb, masterKey)

	return nil
}

// Add a local endpoint.
// This takes ofp port number, mac address, vlan , VrfId and IP address of the port.
func (self *OfnetAgent) AddLocalEndpoint(endpoint EndpointInfo) error {
	// Add port vlan mapping
	self.portVlanMap[endpoint.PortNo] = &endpoint.Vlan

	// Map Vlan to VNI
	vni := self.vlanVniMap[endpoint.Vlan]
	if vni == nil {
		log.Errorf("VNI for vlan %d is not known", endpoint.Vlan)
		return errors.New("Unknown Vlan")
	}

	epId := self.getEndpointId(endpoint)

	// Build endpoint registry info
	epreg := &OfnetEndpoint{
		EndpointID:    epId,
		EndpointType:  "internal",
		EndpointGroup: endpoint.EndpointGroup,
		IpAddr:        endpoint.IpAddr,
		IpMask:        net.ParseIP("255.255.255.255"),
		VrfId:         endpoint.Vlan, //This has to be changed to vrfId when there is multi network per vrf support
		MacAddrStr:    endpoint.MacAddr.String(),
		Vlan:          endpoint.Vlan,
		Vni:           *vni,
		OriginatorIp:  self.localIp,
		PortNo:        endpoint.PortNo,
		Timestamp:     time.Now(),
	}

	// Call the datapath
	err := self.datapath.AddLocalEndpoint(*epreg)
	if err != nil {
		log.Errorf("Adding endpoint (%+v) to datapath. Err: %v", epreg, err)
		return err
	}

	// Add the endpoint to local routing table
	self.endpointDb[epId] = epreg
	self.localEndpointDb[endpoint.PortNo] = epreg

	// Send the endpoint to all known masters
	for _, master := range self.masterDb {
		var resp bool

		log.Infof("Sending endpoint %+v to master %+v", epreg, master)

		// Make the RPC call to add the endpoint to master
		err := rpcHub.Client(master.HostAddr, master.HostPort).Call("OfnetMaster.EndpointAdd", epreg, &resp)
		if err != nil {
			log.Errorf("Failed to add endpoint %+v to master %+v. Err: %v", epreg, master, err)
			return err
		}
	}

	return nil
}

// Remove local endpoint
func (self *OfnetAgent) RemoveLocalEndpoint(portNo uint32) error {
	// Clear it from DB
	delete(self.portVlanMap, portNo)

	epreg := self.localEndpointDb[portNo]
	if epreg == nil {
		log.Errorf("Endpoint not found for port %d", portNo)
		return errors.New("Endpoint not found")
	}

	// Call the datapath
	err := self.datapath.RemoveLocalEndpoint(*epreg)
	if err != nil {
		log.Errorf("Error deleting endpointon port %d. Err: %v", portNo, err)
	}

	// delete the endpoint from local endpoint table
	delete(self.endpointDb, epreg.EndpointID)
	delete(self.localEndpointDb, portNo)

	// Send the DELETE to all known masters
	for _, master := range self.masterDb {
		var resp bool

		log.Infof("Sending DELETE endpoint %+v to master %+v", epreg, master)

		// Make the RPC call to delete the endpoint on master
		client := rpcHub.Client(master.HostAddr, master.HostPort)
		err := client.Call("OfnetMaster.EndpointDel", epreg, &resp)
		if err != nil {
			log.Errorf("Failed to DELETE endpoint %+v on master %+v. Err: %v", epreg, master, err)
		}
	}

	return nil
}

// Add virtual tunnel end point. This is mainly used for mapping remote vtep IP
// to ofp port number.
func (self *OfnetAgent) AddVtepPort(portNo uint32, remoteIp net.IP) error {
	// Ignore duplicate Add vtep messages
	oldPort, ok := self.vtepTable[remoteIp.String()]
	if ok && *oldPort == portNo {
		return nil
	}

	log.Infof("Adding VTEP port(%d), Remote IP: %v", portNo, remoteIp)

	// Store the vtep IP to port number mapping
	self.vtepTable[remoteIp.String()] = &portNo

	// Call the datapath
	return self.datapath.AddVtepPort(portNo, remoteIp)
}

// Remove a VTEP port
func (self *OfnetAgent) RemoveVtepPort(portNo uint32, remoteIp net.IP) error {
	// Clear the vtep IP to port number mapping
	delete(self.vtepTable, remoteIp.String())

	// walk all the endpoints and uninstall the ones pointing at remote host
	for _, endpoint := range self.endpointDb {
		// Find all the routes pointing at the remote VTEP
		if endpoint.OriginatorIp.String() == remoteIp.String() {
			var resp bool
			// Uninstall the route from HW
			err := self.EndpointDel(endpoint, &resp)
			if err != nil {
				log.Errorf("Error uninstalling endpoint %+v. Err: %v", endpoint, err)
			}
		}
	}

	// Call the datapath
	return self.datapath.RemoveVtepPort(portNo, remoteIp)
}

// Add a Network.
// This is mainly used for mapping vlan id to Vxlan VNI and add gateway for network
func (self *OfnetAgent) AddNetwork(vlanId uint16, vni uint32, Gw string) error {
	// store it in DB
	self.vlanVniMap[vlanId] = &vni
	self.vniVlanMap[vni] = &vlanId
	if Gw != "" {
		// Call the datapath
		epreg := &OfnetEndpoint{
			EndpointID:   Gw,
			EndpointType: "internal",
			IpAddr:       net.ParseIP(Gw),
			IpMask:       net.ParseIP("255.255.255.255"),
			VrfId:        0, // FIXME set VRF correctly
			Vlan:         1,
			PortNo:       0,
			Timestamp:    time.Now(),
		}
		self.endpointDb[Gw] = epreg
		return self.datapath.AddVlan(vlanId, vni)
	}
	return nil

}

// Remove a vlan from datapath
func (self *OfnetAgent) RemoveNetwork(vlanId uint16, vni uint32, Gw string) error {
	// Clear the database
	delete(self.vlanVniMap, vlanId)
	delete(self.vniVlanMap, vni)

	// make sure there are no endpoints still installed in this vlan
	for _, endpoint := range self.endpointDb {
		if endpoint.Vni == vni {
			log.Fatalf("Vlan %d still has routes. Route: %+v", vlanId, endpoint)
		}
	}
	delete(self.endpointDb, Gw)

	// Call the datapath
	return self.datapath.RemoveVlan(vlanId, vni)
}

// Add remote endpoint RPC call from master
func (self *OfnetAgent) EndpointAdd(epreg *OfnetEndpoint, ret *bool) error {
	log.Infof("EndpointAdd rpc call for endpoint: %+v. localIp: %v", epreg, self.localIp)

	// If this is a local endpoint we are done
	if epreg.OriginatorIp.String() == self.localIp.String() {
		return nil
	}

	// Check if we have the endpoint already and which is more recent
	oldEp := self.endpointDb[epreg.EndpointID]
	if oldEp != nil {
		// If old endpoint has more recent timestamp, nothing to do
		if !epreg.Timestamp.After(oldEp.Timestamp) {
			return nil
		}

		// Uninstall the old endpoint from datapath
		err := self.datapath.RemoveEndpoint(oldEp)
		if err != nil {
			log.Errorf("Error deleting old endpoint: {%+v}. Err: %v", oldEp, err)
		}
	}

	// First, add the endpoint to local routing table
	self.endpointDb[epreg.EndpointID] = epreg

	// Lookup the VTEP for the endpoint
	vtepPort := self.vtepTable[epreg.OriginatorIp.String()]
	if vtepPort == nil {
		log.Errorf("Could not find the VTEP for endpoint: %+v", epreg)

		return errors.New("VTEP not found")
	}

	// Install the endpoint in datapath
	err := self.datapath.AddEndpoint(epreg)
	if err != nil {
		log.Errorf("Error adding endpoint: {%+v}. Err: %v", epreg, err)
		return err
	}

	return nil
}

// Delete remote endpoint RPC call from master
func (self *OfnetAgent) EndpointDel(epreg *OfnetEndpoint, ret *bool) error {
	// If this is a local endpoint we are done
	if epreg.OriginatorIp.String() == self.localIp.String() {
		return nil
	}

	// Ignore duplicate delete requests we might receive from multiple
	// Ofnet masters
	if self.endpointDb[epreg.EndpointID] == nil {
		return nil
	}

	// Uninstall the endpoint from datapath
	err := self.datapath.RemoveEndpoint(epreg)
	if err != nil {
		log.Errorf("Error deleting endpoint: {%+v}. Err: %v", epreg, err)
	}

	// Remove it from endpoint table
	delete(self.endpointDb, epreg.EndpointID)

	return nil
}

func (self *OfnetAgent) DummyRpc(arg *string, ret *bool) error {
	log.Infof("Received dummy route RPC call")
	return nil
}

/*
Bgp serve routine does the following:
1) Creates inb01 router port
2) Add MyBgp endpoint
3) Kicks off routines to monitor route updates and peer state
*/
func (self *OfnetAgent) Serve() error {
	time.Sleep(5 * time.Second)
	self.WaitForSwitchConnection()

	self.modRibCh = make(chan *api.Path, 16)
	self.advPathCh = make(chan *api.Path, 16)

	timeout := grpc.WithTimeout(time.Second)
	conn, err := grpc.Dial("127.0.0.1:8080", timeout, grpc.WithBlock(), grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}
	client := api.NewGobgpApiClient(conn)
	if client == nil {

	}
	path := &api.Path{
		Pattrs: make([][]byte, 0),
	}

	routerId := self.routerIP
	if len(routerId) == 0 {
		log.Errorf("Invalid router IP. Bgp service aborted")
		return errors.New("Invalid router IP")
	}
	path.Nlri, _ = bgp.NewIPAddrPrefix(uint8(32), routerId).Serialize()
	n, _ := bgp.NewPathAttributeNextHop("0.0.0.0").Serialize()
	path.Pattrs = append(path.Pattrs, n)
	origin, _ := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE).Serialize()
	path.Pattrs = append(path.Pattrs, origin)

	err = self.ovsDriver.CreatePort("inb01", "internal", 1)
	if err != nil {
		log.Errorf("Error creating the port", err)
		return err
	}

	cmd := exec.Command("ifconfig", "inb01", routerId+"/24")
	cmd.Run()

	intf, _ := net.InterfaceByName("inb01")
	ofPortno, _ := self.ovsDriver.GetOfpPortNo("inb01")

	if intf == nil || ofPortno == 0 {
		log.Errorf("Error fetching inb01 information", intf, ofPortno)
		return errors.New("Unable to fetch inb01 info")
	}

	epreg := &OfnetEndpoint{
		EndpointID:   routerId,
		EndpointType: "internal-bgp",
		IpAddr:       net.ParseIP(routerId),
		IpMask:       net.ParseIP("255.255.255.255"),
		VrfId:        0,                          // FIXME set VRF correctly
		MacAddrStr:   intf.HardwareAddr.String(), //link.Attrs().HardwareAddr.String(),
		Vlan:         1,
		PortNo:       ofPortno,
		Timestamp:    time.Now(),
	}
	// Add the endpoint to local routing table
	self.endpointDb[routerId] = epreg
	self.localEndpointDb[epreg.PortNo] = epreg
	fmt.Println(epreg)
	err = self.datapath.AddLocalEndpoint(*epreg)

	//Add bgp router id as well
	bgpGlobalCfg := bgpconf.Global{}
	SetDefaultGlobalConfigValues(&bgpGlobalCfg)
	bgpGlobalCfg.GlobalConfig.RouterId = net.ParseIP(routerId)
	bgpGlobalCfg.GlobalConfig.As = 65002
	self.bgpServer.SetGlobalType(bgpGlobalCfg)

	self.advPathCh <- path

	//monitor route updates from peer
	go self.monitorBest()
	//monitor peer state
	go self.monitorPeer()

	for {
		select {
		case p := <-self.modRibCh:
			err = self.modRib(p)
			if err != nil {
				log.Error("failed to mod rib: ", err)
			}
		case p := <-self.advPathCh:
			//err = self.advPath(p)
			if err != nil {
				log.Error("failed to adv path: ", err, p)
			}
		}
	}
}

//monitorBest monitors for route updates/changes form peer
func (self *OfnetAgent) monitorBest() error {

	timeout := grpc.WithTimeout(time.Second)
	conn, err := grpc.Dial("127.0.0.1:8080", timeout, grpc.WithBlock(), grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	client := api.NewGobgpApiClient(conn)
	if client == nil {

	}
	arg := &api.Arguments{
		Resource: api.Resource_GLOBAL,
		Rf:       uint32(bgp.RF_IPv4_UC),
	}

	stream, err := client.MonitorBestChanged(context.Background(), arg)
	if err != nil {
		return err
	}

	for {
		dst, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		self.modRibCh <- dst.Paths[0]
	}
	return nil
}

//Modrib receives route updates from BGP server and adds the endpoint
func (self *OfnetAgent) modRib(path *api.Path) error {
	var nlri bgp.AddrPrefixInterface
	var nextHop string
	var macAddrStr string
	var portNo uint32
	if len(path.Nlri) > 0 {
		nlri = &bgp.IPAddrPrefix{}
		err := nlri.DecodeFromBytes(path.Nlri)
		if err != nil {
			return err
		}
	}

	for _, attr := range path.Pattrs {
		p, err := bgp.GetPathAttribute(attr)
		if err != nil {
			return err
		}

		err = p.DecodeFromBytes(attr)
		if err != nil {
			return err
		}

		if p.GetType() == bgp.BGP_ATTR_TYPE_NEXT_HOP {
			nextHop = p.(*bgp.PathAttributeNextHop).Value.String()
			break
		}
	}
	if nextHop == "0.0.0.0" {
		return nil
	}

	if nlri == nil {
		return fmt.Errorf("no nlri")
	}

	endpointIPNet, _ := netlink.ParseIPNet(nlri.String())
	log.Infof("Bgp Rib Received endpoint update for %v , with nexthop %v", endpointIPNet, nextHop)

	//check if bgp published a route local to the host
	epid := endpointIPNet.IP.Mask(endpointIPNet.Mask).String()

	//Check if the route is local
	if nextHop == self.routerIP {
		log.Info("This is a local route skipping endpoint create! ")
		return nil
	}

	if self.endpointDb[nextHop] == nil {
		//the nexthop is not the directly connected eBgp peer
		macAddrStr = ""
		portNo = 0
	} else {
		macAddrStr = self.endpointDb[nextHop].MacAddrStr
		portNo = self.endpointDb[nextHop].PortNo
	}

	ipmask := net.ParseIP("255.255.255.255").Mask(endpointIPNet.Mask)

	if path.IsWithdraw != true {
		epreg := &OfnetEndpoint{
			EndpointID:   epid,
			EndpointType: "external",
			IpAddr:       endpointIPNet.IP,
			IpMask:       ipmask,
			VrfId:        0, // FIXME set VRF correctly
			MacAddrStr:   macAddrStr,
			Vlan:         1,
			OriginatorIp: self.localIp,
			PortNo:       portNo,
			Timestamp:    time.Now(),
		}

		// Install the endpoint in datapath
		// First, add the endpoint to local routing table
		self.endpointDb[epreg.EndpointID] = epreg
		err := self.datapath.AddEndpoint(epreg)
		if err != nil {
			log.Errorf("Error adding endpoint: {%+v}. Err: %v", epreg, err)
			return err
		}
	} else {
		log.Info("Received route withdraw from BGP for ", endpointIPNet)
		endpoint := self.getEndpointByIp(endpointIPNet.IP)
		self.datapath.RemoveEndpoint(endpoint)
		delete(self.endpointDb, endpoint.EndpointID)
	}
	return nil
}

//CreateBgpServer creates and starts a bgp server and correspoinding grpc server
func CreateBgpServer() (bgpServer *bgpserver.BgpServer, grpcServer *bgpserver.Server) {
	bgpServer = bgpserver.NewBgpServer(bgp.BGP_PORT)
	if bgpServer == nil {
		log.Errorf("Error creating bgp server")
	}
	go bgpServer.Serve()
	// start grpc Server
	grpcServer = bgpserver.NewGrpcServer(bgpserver.GRPC_PORT, bgpServer.GrpcReqCh)
	if grpcServer == nil {
		log.Errorf("Error creating bgp server")
	}
	go grpcServer.Serve()
	return
}

//DeleteBgpNeighbors deletes bgp neighbor for the host
func (self *OfnetAgent) DeleteBgpNeighbors() error {

	/*As a part of delete bgp neighbors
	1) Search for BGP peer and remove from Bgp.
	2) Delete endpoint info for peer
	3) Finally delete all routes learnt on the nexthop bgp port.
	4) Mark the routes learn via json rpc as unresolved
	*/

	timeout := grpc.WithTimeout(time.Second)
	conn, err := grpc.Dial("127.0.0.1:8080", timeout, grpc.WithBlock(), grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	client := api.NewGobgpApiClient(conn)
	if client == nil {

	}
	arg := &api.Arguments{Name: self.myBgpPeer}

	peer, err := client.GetNeighbor(context.Background(), arg)
	if err != nil {
		log.Errorf("GetNeighbor failed ", err)
		return err
	}
	log.Infof("Deleteing Bgp peer from Bgp server")
	p := bgpconf.Neighbor{}
	SetNeighborConfigValues(&p)

	p.NeighborAddress = net.ParseIP(peer.Conf.NeighborAddress)
	p.NeighborConfig.NeighborAddress = net.ParseIP(peer.Conf.NeighborAddress)
	p.NeighborConfig.PeerAs = uint32(peer.Conf.PeerAs)
	//FIX ME set ipv6 depending on peerip (for v6 BGP)
	p.AfiSafis.AfiSafiList = []bgpconf.AfiSafi{
		bgpconf.AfiSafi{AfiSafiName: "ipv4-unicast"}}
	self.bgpServer.SetBmpConfig(bgpconf.BmpServers{
		BmpServerList: []bgpconf.BmpServer{},
	})
	self.bgpServer.PeerDelete(p)
	bgpEndpoint := self.getEndpointByIp(net.ParseIP(self.myBgpPeer))
	self.datapath.RemoveEndpoint(bgpEndpoint)
	delete(self.endpointDb, self.myBgpPeer)

	uplink, _ := self.ovsDriver.GetOfpPortNo(self.vlanIntf)

	for _, endpoint := range self.endpointDb {
		if endpoint.PortNo == uplink {
			self.datapath.RemoveEndpoint(endpoint)
			if endpoint.EndpointType == "internal" {
				endpoint.PortNo = 0
				self.endpointDb[endpoint.EndpointID] = endpoint
				//We readd unresolved endpoints that were learnt via
				//etcd
				self.datapath.AddEndpoint(endpoint)
			} else if endpoint.EndpointType == "external" {
				delete(self.endpointDb, endpoint.EndpointID)
			}
		}
	}
	return nil

}

//AddBgpNeighbors add bgp neighbor
func (self *OfnetAgent) AddBgpNeighbors(As string, peer string) error {

	var policyConfig bgpconf.RoutingPolicy
	peerAs, _ := strconv.Atoi(As)
	p := bgpconf.Neighbor{}
	SetNeighborConfigValues(&p)
	p.NeighborAddress = net.ParseIP(peer)
	p.NeighborConfig.NeighborAddress = net.ParseIP(peer)
	p.NeighborConfig.PeerAs = uint32(peerAs)

	//FIX ME set ipv6 depending on peerip (for v6 BGP)
	p.AfiSafis.AfiSafiList = []bgpconf.AfiSafi{
		bgpconf.AfiSafi{AfiSafiName: "ipv4-unicast"}}
	log.Infof("Peer %v is added", p.NeighborConfig.NeighborAddress)
	self.bgpServer.SetBmpConfig(bgpconf.BmpServers{
		BmpServerList: []bgpconf.BmpServer{},
	})
	log.Infof("Peer %v is added   3 ", p.NeighborConfig.NeighborAddress)
	self.bgpServer.PeerAdd(p)
	//	if policyConfig == nil {
	//policyConfig = &newConfig.Policy
	self.bgpServer.SetPolicy(policyConfig)
	//	} else {
	//if bgpconf.CheckPolicyDifference(policyConfig, &newConfig.Policy) {
	//	log.Info("Policy config is updated")
	//	bgpServer.UpdatePolicy(newConfig.Policy)
	//}
	//	}

	log.Infof("Peer %v is added", p.NeighborConfig.NeighborAddress)
	epreg := &OfnetEndpoint{
		EndpointID:   peer,
		EndpointType: "external-bgp",
		IpAddr:       net.ParseIP(peer),
		IpMask:       net.ParseIP("255.255.255.255"),
		VrfId:        0, // FIXME set VRF correctly
		Vlan:         1,
		Timestamp:    time.Now(),
	}

	// Install the endpoint in datapath
	// First, add the endpoint to local routing table
	self.endpointDb[epreg.EndpointID] = epreg
	err := self.datapath.AddEndpoint(epreg)

	if err != nil {
		log.Errorf("Error adding endpoint: {%+v}. Err: %v", epreg, err)
		return err
	}
	self.myBgpPeer = peer
	return nil
}

//SetDefaultGlobalConfigValues sets the default global configs for bgp
func SetDefaultGlobalConfigValues(bt *bgpconf.Global) error {

	bt.AfiSafis.AfiSafiList = []bgpconf.AfiSafi{
		bgpconf.AfiSafi{AfiSafiName: "ipv4-unicast"},
		bgpconf.AfiSafi{AfiSafiName: "ipv6-unicast"},
		bgpconf.AfiSafi{AfiSafiName: "l3vpn-ipv4-unicast"},
		bgpconf.AfiSafi{AfiSafiName: "l3vpn-ipv6-unicast"},
		bgpconf.AfiSafi{AfiSafiName: "l2vpn-evpn"},
		bgpconf.AfiSafi{AfiSafiName: "encap"},
		bgpconf.AfiSafi{AfiSafiName: "rtc"},
		bgpconf.AfiSafi{AfiSafiName: "ipv4-flowspec"},
		bgpconf.AfiSafi{AfiSafiName: "l3vpn-ipv4-flowspec"},
		bgpconf.AfiSafi{AfiSafiName: "ipv6-flowspec"},
		bgpconf.AfiSafi{AfiSafiName: "l3vpn-ipv6-flowspec"},
	}
	bt.MplsLabelRange.MinLabel = bgpconf.DEFAULT_MPLS_LABEL_MIN
	bt.MplsLabelRange.MaxLabel = bgpconf.DEFAULT_MPLS_LABEL_MAX

	return nil
}

//SetNeighborConfigValues sets the default neighbor configs for bgp
func SetNeighborConfigValues(neighbor *bgpconf.Neighbor) error {

	timerConfig := neighbor.Timers.TimersConfig
	timerConfig.HoldTime = float64(bgpconf.DEFAULT_CONNECT_RETRY)
	timerConfig.HoldTime = float64(bgpconf.DEFAULT_HOLDTIME)
	timerConfig.KeepaliveInterval = timerConfig.HoldTime / 3
	timerConfig.IdleHoldTimeAfterReset = float64(bgpconf.DEFAULT_IDLE_HOLDTIME_AFTER_RESET)
	//FIX ME need to check with global peer to set internal or external
	neighbor.NeighborConfig.PeerType = bgpconf.PEER_TYPE_INTERNAL

	return nil
}

// monitorPeer is used to monitor the bgp peer state
func (self *OfnetAgent) monitorPeer() error {

	var oldAdminState, oldState string

	timeout := grpc.WithTimeout(time.Second)
	conn, err := grpc.Dial("127.0.0.1:8080", timeout, grpc.WithBlock(), grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	client := api.NewGobgpApiClient(conn)
	if client == nil {

	}
	arg := &api.Arguments{}

	stream, err := client.MonitorPeerState(context.Background(), arg)
	if err != nil {
		log.Errorf("MonitorPeerState failed ", err)
		return err
	}
	for {
		s, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Errorf("MonitorPeerState stream failed :", err)
			break
		}
		fmt.Printf("[NEIGH] %s fsm: %s admin: %s\n", s.Conf.NeighborAddress, s.Info.BgpState, s.Info.AdminState)
		if oldState == "BGP_FSM_ESTABLISHED" && oldAdminState == "ADMIN_STATE_UP" {
			uplink, _ := self.ovsDriver.GetOfpPortNo(self.vlanIntf)
			/*If the state changed from being established to idle or active:
			   1) delete all endpoints learnt via bgp Peer
				 2) mark routes pointing to the bgp nexthop as unresolved
				 3) mark the bgp peer reachbility as unresolved
			*/
			for _, endpoint := range self.endpointDb {
				if endpoint.PortNo == uplink {
					self.datapath.RemoveEndpoint(endpoint)
					if endpoint.EndpointType == "internal" {
						endpoint.PortNo = 0
						self.endpointDb[endpoint.EndpointID] = endpoint
						//We readd unresolved endpoints that were learnt via
						//json rpc
						self.datapath.AddEndpoint(endpoint)
					} else if endpoint.EndpointType == "external" {
						delete(self.endpointDb, endpoint.EndpointID)
					} else if endpoint.EndpointType == "external-bgp" {
						// bgp peer endpoint
						endpoint.PortNo = 0
						self.endpointDb[endpoint.EndpointID] = endpoint
						self.datapath.AddEndpoint(endpoint)
					}
				}
			}
		}
		oldState = s.Info.BgpState
		oldAdminState = s.Info.AdminState
	}
	return nil
}

/*ShowRib api to dump BGP RIB
func (self *OfnetAgent) ShowRib() error {

	timeout := grpc.WithTimeout(time.Second)
	conn, err := grpc.Dial("127.0.0.1:8080", timeout, grpc.WithBlock(), grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	client := api.NewGobgpApiClient(conn)
	if client == nil {

	}

	arg := &api.Table{
		Type:   api.Resource_GLOBAL,
		Family: uint32(bgp.RF_IPv4_UC),
	}

	rib, err := client.GetRib(context.Background(), arg)
	if err != nil {
		fmt.Println("returnin Error", err)
		return err
	}

	return nil

}
*/
