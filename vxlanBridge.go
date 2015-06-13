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
// This file implements the vxlan bridging datapath

import (
    //"fmt"
    "net"
    "net/rpc"
    "time"
    "errors"

    //"github.com/shaleman/libOpenflow/openflow13"
    //"github.com/shaleman/libOpenflow/protocol"
    "github.com/contiv/ofnet/ofctrl"
    "github.com/contiv/ofnet/rpcHub"

    log "github.com/Sirupsen/logrus"
)

// VXLAN tables are structured as follows
//
// +-------+
// | Valid |                                               +--------------+
// | Pkts  +-->+-------+                               +-->| Ucast Output |
// +-------+   | Vlan  |   +----------+                |   +--------------+
//             | Table +-->| Mac Src  |   +---------+  |
//             +-------+   | Learning +-->| Mac Dst |  |   +--------+
//                         +----------+   | Lookup  +--+-->| Flood  |
//                                        +---------+      | Filter |
//                                                         +--+-----+
//                                                            |
//                                     +--------------------------+
//                                     V                          V
//                            +------------------+    +----------------------+
//                            | Local Only Flood |    | Local + Remote Flood |
//                            +------------------+    +----------------------+
//

// Vxlan state.
type Vxlan struct {
    agent       *OfnetAgent             // Pointer back to ofnet agent that owns this
    ofSwitch    *ofctrl.OFSwitch        // openflow switch we are talking to

    vlanDb      map[uint16]*Vlan        // Database of known vlans

    // Mac route table
    macRouteDb      map[string]*MacRoute

    // Fgraph tables
    inputTable      *ofctrl.Table       // Packet lookup starts here
    vlanTable       *ofctrl.Table       // Vlan Table. map port or VNI to vlan
    macDestTable    *ofctrl.Table
    floodTable      *ofctrl.Table

    // Flow Database
    macFlowDb       map[string]*ofctrl.Flow // Database of flow entries
}

// Vlan info
type Vlan struct {
    Vni             uint32                  // Vxlan VNI
    localPortList   map[uint32]*uint32      // List of local ports only
    allPortList     map[uint32]*uint32      // List of local + remote(vtep) ports
    localFlood      *ofctrl.Flood           // local only flood list
    allFlood        *ofctrl.Flood           // local + remote flood list
}

// Mac address info
type MacRoute struct {
    MacAddrStr      string          // Mac address of the end point(in string format)
    Vni             uint32          // Vxlan VNI
    OriginatorIp    net.IP          // Originating switch
    PortNo          uint32          // Port number on originating switch
    Timestamp       time.Time       // Timestamp of the last event
}

const METADATA_RX_VTEP = 0x1

// Create a new vxlan instance
func NewVxlan(agent *OfnetAgent, rpcServ *rpc.Server) *Vxlan {
    vxlan := new(Vxlan)

    // Keep a reference to the agent
    vxlan.agent = agent

    // init DBs
    vxlan.macRouteDb = make(map[string]*MacRoute)
    vxlan.vlanDb     = make(map[uint16]*Vlan)
    vxlan.macFlowDb  = make(map[string]*ofctrl.Flow)

    // Register for Route rpc callbacks
    rpcServ.Register(vxlan)

    return vxlan
}

// Handle switch connected notification
func (self *Vxlan) SwitchConnected(sw *ofctrl.OFSwitch) {
    // Keep a reference to the switch
    self.ofSwitch = sw

    // Init the Fgraph
    self.initFgraph()

    log.Infof("Switch connected(vxlan). adding default vlan")
}

// Handle switch disconnected notification
func (self *Vxlan) SwitchDisconnected(sw *ofctrl.OFSwitch) {
    // FIXME: ??
}

// Handle incoming packet
func (self *Vxlan) PacketRcvd(sw *ofctrl.OFSwitch, pkt *ofctrl.PacketIn) {
}

// Add a local endpoint and install associated local route
func (self *Vxlan) AddLocalEndpoint(endpoint EndpointInfo) error {
    // Install a flow entry for vlan mapping and point it to IP table
    portVlanFlow, err := self.vlanTable.NewFlow(ofctrl.FlowMatch{
                            Priority: FLOW_MATCH_PRIORITY,
                            InputPort: endpoint.PortNo,
                        })
    if err != nil {
        log.Errorf("Error creating portvlan entry. Err: %v", err)
        return err
    }

    // Set the vlan and install it
    portVlanFlow.SetVlan(endpoint.Vlan)
    err = portVlanFlow.Next(self.macDestTable)
    if err != nil {
        log.Errorf("Error installing portvlan entry. Err: %v", err)
        return err
    }

    // Add the port to local and remote flood list
    vlan := self.vlanDb[endpoint.Vlan]
    output, _ := self.ofSwitch.OutputPort(endpoint.PortNo)
    vlan.localFlood.AddOutput(output)
    vlan.allFlood.AddOutput(output)

    // Finally install the mac address
    macFlow, _ := self.macDestTable.NewFlow(ofctrl.FlowMatch{
                            Priority: FLOW_MATCH_PRIORITY,
                            VlanId: endpoint.Vlan,
                            MacDa: &endpoint.MacAddr,
                        })
    macFlow.PopVlan()
    macFlow.Next(output)

    // Build the mac route
    macRoute := MacRoute{
                    MacAddrStr: endpoint.MacAddr.String(),
                    Vni: *(self.agent.vlanVniMap[endpoint.Vlan]),
                    OriginatorIp: self.agent.localIp,
                    PortNo: endpoint.PortNo,
                    Timestamp: time.Now(),
                }

    // Advertize the route to master
    err = self.localRouteAdd(&macRoute)
    if (err != nil) {
        log.Errorf("Failed to add route %+v to master. Err: %v", macRoute, err)
        return err
    }

    return nil
}

// Remove local endpoint
func (self *Vxlan) RemoveLocalEndpoint(portNo uint32) error {
    return nil
}

// Add virtual tunnel end point. This is mainly used for mapping remote vtep IP
// to ofp port number.
func (self *Vxlan) AddVtepPort(portNo uint32, remoteIp net.IP) error {
    // Install VNI to vlan mapping for each vni
    for vni, vlan := range self.agent.vniVlanMap {
        // Install a flow entry for  VNI/vlan and point it to macDest table
        portVlanFlow, _ := self.vlanTable.NewFlow(ofctrl.FlowMatch{
                                Priority: FLOW_MATCH_PRIORITY,
                                InputPort: portNo,
                                TunnelId: uint64(vni),
                            })
        portVlanFlow.SetVlan(*vlan)

        // Set the metadata to indicate packet came in from VTEP port
        portVlanFlow.SetMetadata(METADATA_RX_VTEP, METADATA_RX_VTEP)

        // Point to next table
        portVlanFlow.Next(self.macDestTable)
    }

    // Walk all vlans and add vtep port to the vlan
    for vlanId, vlan := range self.vlanDb {
        vni := self.agent.vlanVniMap[vlanId]
        if vni == nil {
            log.Errorf("Can not find vni for vlan: %d", vlanId)
        }
        output, _ := self.ofSwitch.OutputPort(portNo)
        vlan.allFlood.AddTunnelOutput(output, uint64(*vni))
    }
    return nil
}

// Remove a VTEP port
func (self *Vxlan) RemoveVtepPort(portNo uint32, remoteIp net.IP) error {
    return nil
}

// Add a vlan.
func (self *Vxlan) AddVlan(vlanId uint16, vni uint32) error {
    vlan := new(Vlan)
    vlan.Vni = vni
    vlan.localPortList = make(map[uint32]*uint32)
    vlan.allPortList = make(map[uint32]*uint32)

    // Create flood entries
    vlan.localFlood, _ = self.ofSwitch.NewFlood()
    vlan.allFlood, _ = self.ofSwitch.NewFlood()

    // Walk all VTEP ports and add vni-vlan mapping for new VNI
    for _, vtepPort := range self.agent.vtepTable {
        // Install a flow entry for  VNI/vlan and point it to macDest table
        portVlanFlow, _ := self.vlanTable.NewFlow(ofctrl.FlowMatch{
                                Priority: FLOW_MATCH_PRIORITY,
                                InputPort: *vtepPort,
                                TunnelId: uint64(vni),
                            })
        portVlanFlow.SetVlan(vlanId)

        // Set the metadata to indicate packet came in from VTEP port
        portVlanFlow.SetMetadata(METADATA_RX_VTEP, METADATA_RX_VTEP)

        // Point to next table
        portVlanFlow.Next(self.macDestTable)
    }

    // Walk all VTEP ports and add it to the allFlood list
    for _, vtepPort := range self.agent.vtepTable {
        output, _ := self.ofSwitch.OutputPort(*vtepPort)
        vlan.allFlood.AddTunnelOutput(output, uint64(vni))
    }

    log.Infof("Installing vlan flood entry for vlan: %d", vlanId)

    // Install local flood and remote flood entries in macDestTable
    var metadataLclRx uint64 = 0
    var metadataVtepRx uint64 = METADATA_RX_VTEP
    vlanFlood, _ := self.macDestTable.NewFlow(ofctrl.FlowMatch{
                            Priority: FLOW_FLOOD_PRIORITY,
                            VlanId: vlanId,
                            Metadata: &metadataLclRx,
                            MetadataMask: &metadataVtepRx,
                        })
    vlanFlood.Next(vlan.allFlood)
    vlanLclFlood, _ := self.macDestTable.NewFlow(ofctrl.FlowMatch{
                            Priority: FLOW_FLOOD_PRIORITY,
                            VlanId: vlanId,
                            Metadata: &metadataVtepRx,
                            MetadataMask: &metadataVtepRx,
                        })
    vlanLclFlood.Next(vlan.localFlood)

    // store it in DB
    self.vlanDb[vlanId] = vlan

    return nil
}

// Remove a vlan
func (self *Vxlan) RemoveVlan(vlanId uint16, vni uint32) error {
    return nil
}

// Mac route add rpc call from master
func (self *Vxlan) MacRouteAdd (macRoute *MacRoute, ret *bool) error {
    log.Infof("Received mac route: %+v", macRoute)

    // If this is a local route we are done
    if (macRoute.OriginatorIp.String() == self.agent.localIp.String()) {
        return nil
    }

    // Check if we have the route already and which is more recent
    oldRoute := self.macRouteDb[macRoute.MacAddrStr]
    if (oldRoute != nil) {
        // If old route has more recent timestamp, nothing to do
        if (oldRoute.Timestamp.After(macRoute.Timestamp)) {
            return nil
        }
    }

    // First, add the route to local routing table
    self.macRouteDb[macRoute.MacAddrStr] = macRoute

    // Lookup the VTEP for the route
    vtepPort := self.agent.vtepTable[macRoute.OriginatorIp.String()]
    if (vtepPort == nil) {
        log.Errorf("Could not find the VTEP for mac route: %+v", macRoute)

        return errors.New("VTEP not found")
    }

    // map VNI to vlan Id
    vlanId := self.agent.vniVlanMap[macRoute.Vni]
    macAddr, _ := net.ParseMAC(macRoute.MacAddrStr)

    // Install the route in OVS
    // Create an output port for the vtep
    outPort, err := self.ofSwitch.OutputPort(*vtepPort)
    if (err != nil) {
        log.Errorf("Error creating output port %d. Err: %v", *vtepPort, err)
        return err
    }

    // Finally install the mac address
    macFlow, _ := self.macDestTable.NewFlow(ofctrl.FlowMatch{
                            Priority: FLOW_MATCH_PRIORITY,
                            VlanId: *vlanId,
                            MacDa: &macAddr,
                        })
    macFlow.PopVlan()
    macFlow.SetTunnelId(uint64(macRoute.Vni))
    macFlow.Next(outPort)

    return nil
}

// Mac route delete rpc call from master
func (self *Vxlan) MacRouteDel (macRoute *MacRoute, ret *bool) error {
    log.Infof("Received DELETE mac route: %+v", macRoute)
    return nil
}

// Add a local route to routing table and distribute it
func (self *Vxlan) localRouteAdd(macRoute *MacRoute) error {
    // First, add the route to local routing table
    self.macRouteDb[macRoute.MacAddrStr] = macRoute

    // Send the route to all known masters
    for masterAddr, _ := range self.agent.masterDb {
        var resp bool

        log.Infof("Sending macRoute %+v to master %s", macRoute, masterAddr)

        // Make the RPC call to add the route to master
        client := rpcHub.Client(masterAddr, OFNET_MASTER_PORT)
        err := client.Call("OfnetMaster.MacRouteAdd", macRoute, &resp)
        if (err != nil) {
            log.Errorf("Failed to add route %+v to master %s. Err: %v", macRoute, masterAddr, err)
            return err
        }
    }

    return nil
}

const MAC_DEST_TBL_ID = 3
const FLOOD_TBL_ID = 4

// initialize Fgraph on the switch
func (self *Vxlan) initFgraph() error {
    sw := self.ofSwitch

    log.Infof("Installing initial flow entries")

    // Create all tables
    self.inputTable = sw.DefaultTable()
    self.vlanTable, _ = sw.NewTable(VLAN_TBL_ID)
    self.macDestTable, _ = sw.NewTable(MAC_DEST_TBL_ID)
    self.floodTable, _ = sw.NewTable(FLOOD_TBL_ID)

    //Create all drop entries
    // Drop mcast source mac
    bcastMac, _ := net.ParseMAC("01:00:00:00:00:00")
    bcastSrcFlow, _ := self.inputTable.NewFlow(ofctrl.FlowMatch{
                            Priority: FLOW_MATCH_PRIORITY,
                            MacSa: &bcastMac,
                            MacSaMask: &bcastMac,
                        })
    bcastSrcFlow.Next(sw.DropAction())


    // Send all valid packets to vlan table
    // This is installed at lower priority so that all packets that miss above
    // flows will match entry
    validPktFlow, _ := self.inputTable.NewFlow(ofctrl.FlowMatch{
                            Priority: FLOW_MISS_PRIORITY,
                        })
    validPktFlow.Next(self.vlanTable)

    // Drop all packets that miss Vlan lookup
    vlanMissFlow, _ := self.vlanTable.NewFlow(ofctrl.FlowMatch{
                            Priority: FLOW_MISS_PRIORITY,
                        })
    vlanMissFlow.Next(sw.DropAction())

    // Drop all packets that miss mac dest lookup AND vlan flood lookup
    floodMissFlow, _ := self.macDestTable.NewFlow(ofctrl.FlowMatch{
                            Priority: FLOW_MISS_PRIORITY,
                        })
    floodMissFlow.Next(sw.DropAction())

    // Drop all
    return nil
}
