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
    //"fmt"
    "net"
    "net/rpc"


    "github.com/contiv/ofnet/ofctrl"
    "github.com/contiv/ofnet/rpcHub"

    log "github.com/Sirupsen/logrus"
)

// OfnetAgent state
type OfnetAgent struct {
    ctrler      *ofctrl.Controller      // Controller instance
    ofSwitch    *ofctrl.OFSwitch        // Switch instance. Assumes single switch per agent
    localIp     net.IP                  // Local IP to be used for tunnel end points

    rpcServ     *rpc.Server             // jsonrpc server
    datapath    OfnetDatapath           // Configured datapath

    masterDb    map[string]*net.IP      // list of Master's IP address

    // Port and VNI to vlan mapping table
    portVlanMap map[uint32]*uint16       // Map port number to vlan
    vniVlanMap  map[uint32]*uint16       // Map VNI to vlan
    vlanVniMap  map[uint16]*uint32       // Map vlan to VNI

    // VTEP database
    vtepTable   map[string]*uint32      // Map vtep IP to OVS port number
}

// local End point information
type EndpointInfo struct {
    PortNo      uint32
    MacAddr     net.HardwareAddr
    Vlan        uint16
    IpAddr      net.IP
}

const FLOW_MATCH_PRIORITY = 100     // Priority for all match flows
const FLOW_FLOOD_PRIORITY = 10      // Priority for flood entries
const FLOW_MISS_PRIORITY = 1        // priority for table miss flow

const OFNET_MASTER_PORT = 9001
const OFNET_AGENT_PORT  = 9002

// Create a new Ofnet agent and initialize it
func NewOfnetAgent(bridge string, dpName string, localIp net.IP) (*OfnetAgent, error) {
    agent := new(OfnetAgent)

    // Init params
    agent.localIp = localIp
    agent.masterDb = make(map[string]*net.IP)
    agent.portVlanMap = make(map[uint32]*uint16)
    agent.vniVlanMap = make(map[uint32]*uint16)
    agent.vlanVniMap = make(map[uint16]*uint32)

    agent.vtepTable = make(map[string]*uint32)

    // Create an openflow controller
    agent.ctrler = ofctrl.NewController(bridge, agent)

    // Start listening to controller port
    go agent.ctrler.Listen(":6633")

    // Create rpc server
    // FIXME: Create this only once instead of per ofnet agent instance
    rpcServ := rpcHub.NewRpcServer(OFNET_AGENT_PORT)
    agent.rpcServ = rpcServ

    // Register for Master add/remove events
    rpcServ.Register(agent)

    // Create the datapath
    switch dpName {
    case "vrouter":
        agent.datapath = NewVrouter(agent, rpcServ)
    case "vxlan":
        agent.datapath = NewVxlan(agent, rpcServ)
    default:
        log.Fatalf("Unknown Datapath %s", dpName)
    }

    // Return it
    return agent, nil
}

// Handle switch connected event
func (self *OfnetAgent) SwitchConnected(sw *ofctrl.OFSwitch) {
    log.Infof("Switch %v connectedd", sw.DPID())

    // store it for future use.
    self.ofSwitch = sw

    // Inform the datapath
    self.datapath.SwitchConnected(sw)

    // add default vlan
    self.AddVlan(1, 1)
}

// Handle switch disconnect event
func (self *OfnetAgent) SwitchDisconnected(sw *ofctrl.OFSwitch) {
    log.Infof("Switch %v disconnected", sw.DPID())

    // Inform the datapath
    self.datapath.SwitchDisconnected(sw)
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
func (self *OfnetAgent) AddMaster(masterAddr *string, ret *bool) error {
    myAddr := self.localIp.String()
    masterIp := net.ParseIP(*masterAddr)
    var resp bool

    log.Infof("Adding master: %s", *masterAddr)

    // Save it in DB
    self.masterDb[*masterAddr] = &masterIp

    // Register the agent with the master
    err := rpcHub.Client(*masterAddr, OFNET_MASTER_PORT).Call("OfnetMaster.RegisterNode", &myAddr, &resp)
    if (err != nil) {
        log.Fatalf("Failed to register with the master %s. Err: %v", masterAddr, err)
        return err
    }

    return nil
}

// Remove the master from master DB
func (self *OfnetAgent) RemoveMaster(masterAddr *string) error {
    log.Infof("Deleting master: %s", *masterAddr)

    // Remove it from DB
    delete(self.masterDb, *masterAddr)

    return nil
}

// Add a local endpoint.
// This takes ofp port number, mac address, vlan and IP address of the port.
func (self *OfnetAgent) AddLocalEndpoint(endpoint EndpointInfo) error {
    // Add port vlan mapping
    self.portVlanMap[endpoint.PortNo] = &endpoint.Vlan

    // Call the datapath
    return self.datapath.AddLocalEndpoint(endpoint)
}

// Remove local endpoint
func (self *OfnetAgent) RemoveLocalEndpoint(portNo uint32) error {
    // Clear it from DB
    delete(self.portVlanMap, portNo)

    // Call the datapath
    return self.datapath.RemoveLocalEndpoint(portNo)
}

// Add virtual tunnel end point. This is mainly used for mapping remote vtep IP
// to ofp port number.
func (self *OfnetAgent) AddVtepPort(portNo uint32, remoteIp net.IP) error {
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

    // Call the datapath
    return self.datapath.RemoveVtepPort(portNo, remoteIp)
}

// Add a vlan.
// This is mainly used for mapping vlan id to Vxlan VNI
func (self *OfnetAgent) AddVlan(vlanId uint16, vni uint32) error {
    // store it in DB
    self.vlanVniMap[vlanId] = &vni
    self.vniVlanMap[vni] = &vlanId

    // Call the datapath
    return self.datapath.AddVlan(vlanId, vni)
}

// Remove a vlan from datapath
func (self *OfnetAgent) RemoveVlan(vlanId uint16, vni uint32) error {
    // Clear the database
    delete(self.vlanVniMap, vlanId)
    delete(self.vniVlanMap, vni)

    // Call the datapath
    return self.datapath.RemoveVlan(vlanId, vni)
}
