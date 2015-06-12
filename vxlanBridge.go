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
    // "errors"

    //"github.com/shaleman/libOpenflow/openflow13"
    //"github.com/shaleman/libOpenflow/protocol"
    "github.com/contiv/ofnet/ofctrl"
    //"github.com/contiv/ofnet/rpcHub"

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
    MacAddr         net.HardwareAddr    // Mac address of the end point
    Vni             uint32              // Vxlan VNI
    OriginatorIp    net.IP              // Originating switch
    PortNo          uint32              // Port number on originating switch
    Timestamp       time.Time           // Timestamp of the last event
}

// Create a new vxlan instance
func NewVxlan(agent *OfnetAgent, rpcServ *rpc.Server) *Vxlan {
    vxlan := new(Vxlan)

    // Keep a reference to the agent
    vxlan.agent = agent

    // init DBs
    vxlan.vlanDb    = make(map[uint16]*Vlan)
    vxlan.macFlowDb = make(map[string]*ofctrl.Flow)

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

    // add default vlan
    self.AddVlan(1, 1)
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

    return nil
}

// Remove local endpoint
func (self *Vxlan) RemoveLocalEndpoint(portNo uint32) error {
    return nil
}

// Add virtual tunnel end point. This is mainly used for mapping remote vtep IP
// to ofp port number.
func (self *Vxlan) AddVtepPort(portNo uint32, remoteIp net.IP) error {
    // Install a flow entry for default VNI/vlan and point it to IP table
    portVlanFlow, _ := self.vlanTable.NewFlow(ofctrl.FlowMatch{
                            Priority: FLOW_MATCH_PRIORITY,
                            InputPort: portNo,
                        })
    // FIXME: Need to match on tunnelId and set vlan-id per VRF
    portVlanFlow.SetVlan(1)
    portVlanFlow.Next(self.macDestTable)

    // Walk all vlans add add vtep port to the vlan
    for _, vlan := range self.vlanDb {
        output, _ := self.ofSwitch.OutputPort(portNo)
        vlan.allFlood.AddOutput(output)
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

    // Walk all VTEP ports and add it to the allFlood list
    for _, vtepPort := range self.agent.vtepTable {
        output, _ := self.ofSwitch.OutputPort(*vtepPort)
        vlan.allFlood.AddOutput(output)
    }

    log.Infof("Installing vlan flood entry for vlan: %d", vlanId)

    // Install local flood and remote flood entries in macDestTable
    vlanFlood, _ := self.macDestTable.NewFlow(ofctrl.FlowMatch{
                            Priority: FLOW_MATCH_PRIORITY,
                            VlanId: vlanId,
                        })
    vlanFlood.Next(vlan.allFlood)

    // store it in DB
    self.vlanDb[vlanId] = vlan

    return nil
}

// Remove a vlan
func (self *Vxlan) RemoveVlan(vlanId uint16, vni uint32) error {
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
