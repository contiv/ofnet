/***
Copyright 2016 Cisco Systems Inc. All rights reserved.

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

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/contiv/ofnet/ofctrl"
	"github.com/shaleman/libOpenflow/openflow13"
	"github.com/shaleman/libOpenflow/protocol"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/ofnet/ovsdbDriver"
)

func addEP(oa *OfnetAgent, portNo uint32, ipAddr string, t *testing.T) {
	macStr := fmt.Sprintf("00:01:02:03:04:%d", portNo)
	macAddr, _ := net.ParseMAC(macStr)
	endpoint := EndpointInfo{
		EndpointGroup: 100,
		PortNo:        portNo,
		MacAddr:       macAddr,
		Vlan:          1,
		IpAddr:        net.ParseIP(ipAddr),
	}

	log.Infof("Adding Local endpoint: %+v", endpoint)

	// Add an Endpoint
	err := oa.AddLocalEndpoint(endpoint)
	if err != nil {
		t.Fatalf("Error adding endpoint. Err: %v", err)
	}
}

func getIPPkt(ipSrc, ipDst string) *ofctrl.PacketIn {
	p := new(ofctrl.PacketIn)
	p.Header = openflow13.NewOfp13Header()
	p.Header.Type = openflow13.Type_PacketIn
	p.BufferId = 0xffffffff
	p.Reason = 0
	p.TableId = 0
	p.Cookie = 0
	p.Match = *openflow13.NewMatch()
	ip := protocol.NewIPv4()
	ip.Version = 4
	ip.IHL = 5
	ip.DSCP = 0
	ip.ECN = 0
	ip.Length = 20
	ip.Protocol = ofctrl.IP_PROTO_TCP
	ip.NWSrc = net.ParseIP(ipSrc)
	ip.NWDst = net.ParseIP(ipDst)

	eth := protocol.NewEthernet()
	eth.Ethertype = protocol.IPv4_MSG
	eth.Data = ip

	p.TableId = SRV_PROXY_DNAT_TBL_ID
	p.Data = *eth
	return p
}

func verifyWatchRemoved(t *testing.T, brName string) {
	flowList, err := ofctlFlowDump(brName)
	if err != nil {
		t.Errorf("Error getting flow entries. Err: %v", err)
		return
	}
	wFlow1 := fmt.Sprintf("priority=10,tcp,nw_dst=10.254.0.10 actions=CONTROLLER")
	wFlow2 := fmt.Sprintf("priority=10,udp,nw_dst=10.254.0.10 actions=CONTROLLER")

	if ofctlFlowMatch(flowList, SRV_PROXY_DNAT_TBL_ID, wFlow1) {
		t.Errorf("Watch TCP flows still present %s", flowList)
	} else {
		log.Infof("Watch TCP flows removed as expected")
	}

	if ofctlFlowMatch(flowList, SRV_PROXY_DNAT_TBL_ID, wFlow2) {
		t.Errorf("Watch UDP flows still present %s", flowList)
	} else {
		log.Infof("Watch UDP flows removed as expected")
	}

}

func verifyNATRemoved(t *testing.T, brName string) {
	flowList, err := ofctlFlowDump(brName)
	if err != nil {
		t.Errorf("Error getting flow entries. Err: %v", err)
		return
	}

	matchStr := "set_field:10.254.0.10->ip_src"
	if ofctlFlowMatch(flowList, SRV_PROXY_SNAT_TBL_ID, matchStr) {
		t.Errorf("SNAT flows still present %s", flowList)
	} else {
		log.Infof("SNAT flows removed as expected")
	}

	matchStr = "set_field:20.1.1.22->ip_dst"
	if ofctlFlowMatch(flowList, SRV_PROXY_DNAT_TBL_ID, matchStr) {
		t.Errorf("DNAT flows still present %s", flowList)
	} else {
		log.Infof("DNAT flows removed as expected")
	}

	// verify watch flows are still there
	wFlow1 := fmt.Sprintf("priority=10,tcp,nw_dst=10.254.0.10 actions=CONTROLLER")
	wFlow2 := fmt.Sprintf("priority=10,udp,nw_dst=10.254.0.10 actions=CONTROLLER")
	checkFlows(t, brName, "Verify tcp watch flows", wFlow1, SRV_PROXY_DNAT_TBL_ID)
	checkFlows(t, brName, "Verify udp watch flows", wFlow2, SRV_PROXY_DNAT_TBL_ID)
}

func verifyEPDel(t *testing.T, brName, epIP string) {
	flowList, err := ofctlFlowDump(brName)
	if err != nil {
		t.Errorf("Error getting flow entries. Err: %v", err)
		return
	}

	matchStr := fmt.Sprintf("tcp,nw_src=%s", epIP)
	if ofctlRawFlowMatch(flowList, matchStr) {
		t.Errorf("DNAT TCP flows still present %s", flowList)
	} else {
		log.Infof("DNAT TCP flows removed as expected")
	}

	matchStr = fmt.Sprintf("udp,nw_src=%s", epIP)
	if ofctlRawFlowMatch(flowList, matchStr) {
		t.Errorf("DNAT UDP flows still present %s", flowList)
	} else {
		log.Infof("DNAT UDP flows removed as expected")
	}

	matchStr = fmt.Sprintf("nw_dst=%s,tp_src=9600", epIP)
	if ofctlRawFlowMatch(flowList, matchStr) {
		t.Errorf("SNAT flows still present %s", flowList)
	} else {
		log.Infof("SNAT flows removed as expected")
	}
}

// Find a flow in flow list and match its action
func ofctlRawFlowMatch(flowList []string, mtStr string) bool {
	for _, flowEntry := range flowList {
		log.Debugf("Looking for %s in %s", mtStr, flowEntry)
		if strings.Contains(flowEntry, mtStr) {
			return true
		}
	}

	return false
}

func verifyLB(t *testing.T, brName string) {
	flowList, err := ofctlFlowDump(brName)
	if err != nil {
		t.Errorf("Error getting flow entries. Err: %v", err)
		return
	}

	matchStr := "set_field:20.1.1.23->ip_dst"
	if ofctlRawFlowMatch(flowList, matchStr) {
		log.Infof("DNAT to 20.1.1.23 found")
	} else {
		t.Errorf("DNAT flows to 20.1.1.23 not found %s", flowList)
	}

	matchStr = "set_field:20.1.1.24->ip_dst"
	if ofctlRawFlowMatch(flowList, matchStr) {
		log.Infof("DNAT to 20.1.24 found")
	} else {
		t.Errorf("DNAT flows to 20.1.1.24 not found %s", flowList)
	}

	matchStr = "tcp,nw_src=20.1.1.23"
	if ofctlRawFlowMatch(flowList, matchStr) {
		log.Infof("SNAT for 20.1.23 found")
	} else {
		t.Errorf("SNAT flows for 20.1.1.23 found %s", flowList)
	}

	matchStr = "tcp,nw_src=20.1.1.24"
	if ofctlRawFlowMatch(flowList, matchStr) {
		log.Infof("SNAT for 20.1.24 found")
	} else {
		t.Errorf("SNAT flows for 20.1.1.24 found %s", flowList)
	}
}

func checkFlows(t *testing.T, brName, hdr, matchStr string, tblId int) {
	log.Infof("##checkFlows##: %s", hdr)
	flowList, err := ofctlFlowDump(brName)
	if err != nil {
		t.Errorf("Error getting flow entries. Err: %v", err)
		return
	}

	if !ofctlFlowMatch(flowList, tblId, matchStr) {
		t.Errorf("Could not find the flow %s in %s", matchStr, flowList)
	} else {
		log.Infof("Found %s in flowList", matchStr)
	}
}

func TestSvcProxyInterface(t *testing.T) {
	var resp bool
	rpcPort := uint16(9600)
	ovsPort := uint16(9601)
	lclIP := net.ParseIP("10.10.10.10")
	ofnetAgent, err := NewOfnetAgent("", "vrouter", lclIP, rpcPort, ovsPort)
	if err != nil {
		t.Fatalf("Error creating ofnet agent. Err: %v", err)
	}

	defer func() { ofnetAgent.Delete() }()

	// Override MyAddr to local host
	ofnetAgent.MyAddr = "127.0.0.1"

	// Create a Master
	ofnetMaster := NewOfnetMaster("", uint16(9602))

	defer func() { ofnetMaster.Delete() }()

	masterInfo := OfnetNode{
		HostAddr: "127.0.0.1",
		HostPort: uint16(9602),
	}

	// connect vrtr agent to master
	err = ofnetAgent.AddMaster(&masterInfo, &resp)
	if err != nil {
		t.Errorf("Error adding master %+v. Err: %v", masterInfo, err)
	}

	log.Infof("Created vrouter ofnet agent: %v", ofnetAgent)

	brName := "ovsbr60"
	ovsDriver := ovsdbDriver.NewOvsDriver(brName)
	err = ovsDriver.AddController("127.0.0.1", ovsPort)
	if err != nil {
		t.Fatalf("Error adding controller to ovs: %s", brName)
	}

	// Wait for switch to connect to controller
	ofnetAgent.WaitForSwitchConnection()

	// Create a vlan for the endpoint
	ofnetAgent.AddNetwork(1, 1, "", "default")

	// add two endpoints
	addEP(ofnetAgent, 12, "10.2.2.2", t)
	addEP(ofnetAgent, 13, "10.2.2.3", t)

	// Create a service spec
	svcPorts := make([]PortSpec, 3)
	svcPorts[0] = PortSpec{
		Protocol: "TCP",
		SvcPort:  5600,
		ProvPort: 9600,
	}
	svcPorts[1] = PortSpec{
		Protocol: "UDP",
		SvcPort:  5601,
		ProvPort: 9600,
	}
	svcPorts[2] = PortSpec{
		Protocol: "TCP",
		SvcPort:  5602,
		ProvPort: 9602,
	}
	svc := ServiceSpec{
		IpAddress: "10.254.0.10",
		Ports:     svcPorts,
	}
	log.Infof("Adding LipService: %+v", svc)
	ofnetAgent.AddSvcSpec("LipService", &svc)

	// Add providers
	sps := make([]string, 1, 2)
	sps[0] = "20.1.1.22"
	ofnetAgent.SvcProviderUpdate("LipService", sps)

	// At this point watch flows should be set up.
	wFlow1 := fmt.Sprintf("priority=10,tcp,nw_dst=10.254.0.10 actions=CONTROLLER")
	wFlow2 := fmt.Sprintf("priority=10,udp,nw_dst=10.254.0.10 actions=CONTROLLER")
	checkFlows(t, brName, "Verify tcp watch flows", wFlow1, SRV_PROXY_DNAT_TBL_ID)
	checkFlows(t, brName, "Verify udp watch flows", wFlow2, SRV_PROXY_DNAT_TBL_ID)

	// inject a pkt from the EP to the service
	pkt1 := getIPPkt("10.2.2.2", "10.254.0.10")
	ofnetAgent.PacketRcvd(ofnetAgent.ofSwitch, pkt1)
	pkt2 := getIPPkt("10.2.2.3", "10.254.0.10")
	ofnetAgent.PacketRcvd(ofnetAgent.ofSwitch, pkt2)

	// At this point, we should have NAT flows set up.
	dNFlow1 := fmt.Sprintf("priority=100,tcp,nw_src=10.2.2.3,nw_dst=10.254.0.10,tp_dst=5600 actions=set_field:9600->tcp_dst,set_field:20.1.1.22->ip_dst,goto_table:3")
	dNFlow2 := fmt.Sprintf("priority=100,tcp,nw_src=10.2.2.2,nw_dst=10.254.0.10,tp_dst=5600 actions=set_field:9600->tcp_dst,set_field:20.1.1.22->ip_dst,goto_table:3")
	dNFlow3 := fmt.Sprintf("priority=100,tcp,nw_src=10.2.2.3,nw_dst=10.254.0.10,tp_dst=5602 actions=set_field:9602->tcp_dst,set_field:20.1.1.22->ip_dst,goto_table:3")
	dNFlow4 := fmt.Sprintf("priority=100,tcp,nw_src=10.2.2.2,nw_dst=10.254.0.10,tp_dst=5602 actions=set_field:9602->tcp_dst,set_field:20.1.1.22->ip_dst,goto_table:3")
	checkFlows(t, brName, "TCP dNAT flow for 10.2.2.3", dNFlow1, SRV_PROXY_DNAT_TBL_ID)
	checkFlows(t, brName, "TCP dNAT flow for 10.2.2.2", dNFlow2, SRV_PROXY_DNAT_TBL_ID)
	checkFlows(t, brName, "TCP dNAT flow for 10.2.2.3", dNFlow3, SRV_PROXY_DNAT_TBL_ID)
	checkFlows(t, brName, "TCP dNAT flow for 10.2.2.2", dNFlow4, SRV_PROXY_DNAT_TBL_ID)
	dNFlow5 := fmt.Sprintf("priority=100,udp,nw_src=10.2.2.3,nw_dst=10.254.0.10,tp_dst=5601 actions=set_field:9600->udp_dst,set_field:20.1.1.22->ip_dst,goto_table:3")
	dNFlow6 := fmt.Sprintf("priority=100,udp,nw_src=10.2.2.2,nw_dst=10.254.0.10,tp_dst=5601 actions=set_field:9600->udp_dst,set_field:20.1.1.22->ip_dst,goto_table:3")
	checkFlows(t, brName, "UDP dNAT flow for 10.2.2.3", dNFlow5, SRV_PROXY_DNAT_TBL_ID)
	checkFlows(t, brName, "UDP dNAT flow for 10.2.2.2", dNFlow6, SRV_PROXY_DNAT_TBL_ID)

	sNFlow1 := fmt.Sprintf("priority=100,tcp,nw_src=20.1.1.22,nw_dst=10.2.2.2,tp_src=9600 actions=set_field:5600->tcp_src,set_field:10.254.0.10->ip_src")
	sNFlow2 := fmt.Sprintf("priority=100,tcp,nw_src=20.1.1.22,nw_dst=10.2.2.3,tp_src=9600 actions=set_field:5600->tcp_src,set_field:10.254.0.10->ip_src")
	sNFlow3 := fmt.Sprintf("priority=100,tcp,nw_src=20.1.1.22,nw_dst=10.2.2.2,tp_src=9602 actions=set_field:5602->tcp_src,set_field:10.254.0.10->ip_src")
	sNFlow4 := fmt.Sprintf("priority=100,tcp,nw_src=20.1.1.22,nw_dst=10.2.2.3,tp_src=9602 actions=set_field:5602->tcp_src,set_field:10.254.0.10->ip_src")
	checkFlows(t, brName, "TCP sNAT flow for 10.2.2.2", sNFlow1, SRV_PROXY_SNAT_TBL_ID)
	checkFlows(t, brName, "TCP sNAT flow for 10.2.2.3", sNFlow2, SRV_PROXY_SNAT_TBL_ID)
	checkFlows(t, brName, "TCP sNAT flow for 10.2.2.2", sNFlow3, SRV_PROXY_SNAT_TBL_ID)
	checkFlows(t, brName, "TCP sNAT flow for 10.2.2.3", sNFlow4, SRV_PROXY_SNAT_TBL_ID)
	sNFlow5 := fmt.Sprintf("priority=100,udp,nw_src=20.1.1.22,nw_dst=10.2.2.2,tp_src=9600 actions=set_field:5601->udp_src,set_field:10.254.0.10->ip_src")
	sNFlow6 := fmt.Sprintf("priority=100,udp,nw_src=20.1.1.22,nw_dst=10.2.2.3,tp_src=9600 actions=set_field:5601->udp_src,set_field:10.254.0.10->ip_src")
	checkFlows(t, brName, "UDP sNAT flow for 10.2.2.2", sNFlow5, SRV_PROXY_SNAT_TBL_ID)
	checkFlows(t, brName, "UDP sNAT flow for 10.2.2.3", sNFlow6, SRV_PROXY_SNAT_TBL_ID)

	// Issue a provider update with two different providers
	sps[0] = "20.1.1.23"
	sps = append(sps, "20.1.1.24")
	ofnetAgent.SvcProviderUpdate("LipService", sps)

	// now, the NAT flows should have been removed.
	verifyNATRemoved(t, brName)

	// inject packets again
	ofnetAgent.PacketRcvd(ofnetAgent.ofSwitch, pkt2)
	ofnetAgent.PacketRcvd(ofnetAgent.ofSwitch, pkt1)

	// flows should be setup in load balanced manner.
	verifyLB(t, brName)

	// Remove one endpoint
	err = ofnetAgent.RemoveLocalEndpoint(12)
	if err != nil {
		t.Errorf("Error deleting endpoint: Err: %v", err)
		return
	}
	// flows of that ep should be gone
	verifyEPDel(t, brName, "10.2.2.2")

	// add another ep and inject a pkt.
	addEP(ofnetAgent, 14, "10.2.2.4", t)
	pkt3 := getIPPkt("10.2.2.4", "10.254.0.10")
	ofnetAgent.PacketRcvd(ofnetAgent.ofSwitch, pkt3)

	// flows should be setup in load balanced manner.
	verifyLB(t, brName)

	svcPorts[2] = PortSpec{
		Protocol: "TCP",
		SvcPort:  7777,
		ProvPort: 9602,
	}
	updatedSvc := ServiceSpec{
		IpAddress: "10.254.0.10",
		Ports:     svcPorts,
	}
	ofnetAgent.AddSvcSpec("LipService", &updatedSvc)

	// Verify watch flows
	verifyNATRemoved(t, brName)

	// Delete the service
	ofnetAgent.DelSvcSpec("LipService", &updatedSvc)

	// Make sure flows are gone
	verifyWatchRemoved(t, brName)

	// Delete the bridge
	ovsDriver.DeleteBridge(brName)
}
