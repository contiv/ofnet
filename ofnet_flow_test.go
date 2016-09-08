package ofnet

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

// test portVlan and DSCP flows on all four forwarding modes
func TestOfnetPortDscpFlow(t *testing.T) {
	testOfnetPortDscpFlow(t, vrtrAgents[0], "vrtrBridge0")
	testOfnetPortDscpFlow(t, vxlanAgents[0], "vxlanBridge0")
	testOfnetPortDscpFlow(t, vlanAgents[0], "vlanBridge0")
	// FIXME: vlrouter test fails while deleting the local endpoint
	// testOfnetPortDscpFlow(t, vlrtrAgents[0], "vlrtrBridge0")
}

// Test adding local endpoint and verify port vlan flow and dscp flow
func testOfnetPortDscpFlow(t *testing.T, agent *OfnetAgent, brName string) {
	macAddr, _ := net.ParseMAC(fmt.Sprintf("02:02:0B:0B:02:02"))
	ipAddr := net.ParseIP(fmt.Sprintf("11.11.2.2"))
	ipv6Addr := net.ParseIP(fmt.Sprintf("2017::2:2"))
	endpoint := EndpointInfo{
		PortNo:   14,
		MacAddr:  macAddr,
		Vlan:     1,
		IpAddr:   ipAddr,
		Ipv6Addr: ipv6Addr,
		Dscp:     10,
	}

	// Install the local endpoint
	err := agent.AddLocalEndpoint(endpoint)
	if err != nil {
		t.Fatalf("Error installing endpoint: %+v. Err: %v", endpoint, err)
		return
	}

	// get the flow entries
	flowList, err := ofctlFlowDump(brName)
	if err != nil {
		t.Errorf("Error getting flow entries. Err: %v", err)
	}

	// verify port flow
	portVlanFlowMatch := fmt.Sprintf("priority=10,in_port=14 actions=write_metadata:0x100000000/0xff00000000")
	if agent.dpName == "vxlan" {
		portVlanFlowMatch = fmt.Sprintf("priority=10,in_port=14 actions=push_vlan:0x8100,set_field:4097->vlan_vid,write_metadata:0x100000000/0xff00000000")
	}
	if !ofctlFlowMatch(flowList, VLAN_TBL_ID, portVlanFlowMatch) {
		fmt.Printf("Flows:\n%v", strings.Join(flowList, "\n"))
		t.Fatalf("Could not find the flow %s on ovs %s", portVlanFlowMatch, brName)
	}

	// verify dscp v4 flow
	dscpv4FlowMatch := fmt.Sprintf("priority=100,ip,in_port=14 actions=set_field:10->ip_dscp,write_metadata:0x100000000/0xff00000000")
	if agent.dpName == "vxlan" {
		dscpv4FlowMatch = fmt.Sprintf("priority=100,ip,in_port=14 actions=set_field:10->ip_dscp,push_vlan:0x8100,set_field:4097->vlan_vid,write_metadata:0x100000000/0xff00000000")
	}
	if !ofctlFlowMatch(flowList, VLAN_TBL_ID, dscpv4FlowMatch) {
		fmt.Printf("Flows:\n%v", strings.Join(flowList, "\n"))
		t.Fatalf("Could not find the flow %s on ovs %s", dscpv4FlowMatch, brName)
	}

	// verify dscp v6 flow
	dscpv6FlowMatch := fmt.Sprintf("priority=100,ipv6,in_port=14 actions=set_field:10->ip_dscp,write_metadata:0x100000000/0xff00000000")
	if agent.dpName == "vxlan" {
		dscpv6FlowMatch = fmt.Sprintf("priority=100,ipv6,in_port=14 actions=set_field:10->ip_dscp,push_vlan:0x8100,set_field:4097->vlan_vid,write_metadata:0x100000000/0xff00000000")
	}
	if !ofctlFlowMatch(flowList, VLAN_TBL_ID, dscpv6FlowMatch) {
		fmt.Printf("Flows:\n%v", strings.Join(flowList, "\n"))
		t.Fatalf("Could not find the flow %s on ovs %s", dscpv6FlowMatch, brName)
	}

	// update the endpoint with new DSCP value
	endpointInfo := EndpointInfo{
		PortNo: 14,
		Dscp:   20,
	}

	// Install the local endpoint
	err = agent.UpdateLocalEndpoint(endpointInfo)
	if err != nil {
		t.Fatalf("Error updating endpoint: %+v. Err: %v", endpointInfo, err)
		return
	}

	// get the flow entries
	flowList, err = ofctlFlowDump(brName)
	if err != nil {
		t.Errorf("Error getting flow entries. Err: %v", err)
	}

	// verify dscp v4 flow
	dscpv4FlowMatch = fmt.Sprintf("priority=100,ip,in_port=14 actions=set_field:20->ip_dscp,write_metadata:0x100000000/0xff00000000")
	if agent.dpName == "vxlan" {
		dscpv4FlowMatch = fmt.Sprintf("priority=100,ip,in_port=14 actions=set_field:20->ip_dscp,push_vlan:0x8100,set_field:4097->vlan_vid,write_metadata:0x100000000/0xff00000000")
	}
	if !ofctlFlowMatch(flowList, VLAN_TBL_ID, dscpv4FlowMatch) {
		fmt.Printf("Flows:\n%v", strings.Join(flowList, "\n"))
		t.Fatalf("Could not find the flow %s on ovs %s", dscpv4FlowMatch, brName)
	}

	// verify dscp v6 flow
	dscpv6FlowMatch = fmt.Sprintf("priority=100,ipv6,in_port=14 actions=set_field:20->ip_dscp,write_metadata:0x100000000/0xff00000000")
	if agent.dpName == "vxlan" {
		dscpv6FlowMatch = fmt.Sprintf("priority=100,ipv6,in_port=14 actions=set_field:20->ip_dscp,push_vlan:0x8100,set_field:4097->vlan_vid,write_metadata:0x100000000/0xff00000000")
	}
	if !ofctlFlowMatch(flowList, VLAN_TBL_ID, dscpv6FlowMatch) {
		fmt.Printf("Flows:\n%v", strings.Join(flowList, "\n"))
		t.Fatalf("Could not find the flow %s on ovs %s", dscpv6FlowMatch, brName)
	}

	// Clear DSCP value
	endpointInfo = EndpointInfo{
		PortNo: 14,
		Dscp:   0,
	}

	// Install the local endpoint
	err = agent.UpdateLocalEndpoint(endpointInfo)
	if err != nil {
		t.Fatalf("Error updating endpoint: %+v. Err: %v", endpointInfo, err)
		return
	}

	// get the flow entries
	flowList, err = ofctlFlowDump(brName)
	if err != nil {
		t.Errorf("Error getting flow entries. Err: %v", err)
	}

	// verify port flow still exists
	portVlanFlowMatch = fmt.Sprintf("priority=10,in_port=14 actions=write_metadata:0x100000000/0xff00000000")
	if agent.dpName == "vxlan" {
		portVlanFlowMatch = fmt.Sprintf("priority=10,in_port=14 actions=push_vlan:0x8100,set_field:4097->vlan_vid,write_metadata:0x100000000/0xff00000000")
	}
	if !ofctlFlowMatch(flowList, VLAN_TBL_ID, portVlanFlowMatch) {
		fmt.Printf("Flows:\n%v", strings.Join(flowList, "\n"))
		t.Fatalf("Could not find the flow %s on ovs %s", portVlanFlowMatch, brName)
	}

	// verify dscp v4 flow is removed
	dscpv4FlowMatch = fmt.Sprintf("priority=100,ip,in_port=14 actions=set_field:20->ip_dscp,write_metadata:0x100000000/0xff00000000")
	if agent.dpName == "vxlan" {
		dscpv4FlowMatch = fmt.Sprintf("priority=100,ip,in_port=14 actions=set_field:20->ip_dscp,push_vlan:0x8100,set_field:4097->vlan_vid,write_metadata:0x100000000/0xff00000000")
	}
	if ofctlFlowMatch(flowList, VLAN_TBL_ID, dscpv4FlowMatch) {
		fmt.Printf("Flows:\n%v", strings.Join(flowList, "\n"))
		t.Fatalf("Flow %s is still present on ovs %s", dscpv4FlowMatch, brName)
	}

	// verify dscp v6 flow is removed
	dscpv6FlowMatch = fmt.Sprintf("priority=100,ipv6,in_port=14 actions=set_field:20->ip_dscp,write_metadata:0x100000000/0xff00000000")
	if agent.dpName == "vxlan" {
		dscpv6FlowMatch = fmt.Sprintf("priority=100,ipv6,in_port=14 actions=set_field:20->ip_dscp,push_vlan:0x8100,set_field:4097->vlan_vid,write_metadata:0x100000000/0xff00000000")
	}
	if ofctlFlowMatch(flowList, VLAN_TBL_ID, dscpv6FlowMatch) {
		fmt.Printf("Flows:\n%v", strings.Join(flowList, "\n"))
		t.Fatalf("Flow %s is still present on ovs %s", dscpv6FlowMatch, brName)
	}

	// Set new DSCP value
	endpointInfo = EndpointInfo{
		PortNo: 14,
		Dscp:   30,
	}

	// Install the local endpoint
	err = agent.UpdateLocalEndpoint(endpointInfo)
	if err != nil {
		t.Fatalf("Error updating endpoint: %+v. Err: %v", endpointInfo, err)
		return
	}

	// get the flow entries
	flowList, err = ofctlFlowDump(brName)
	if err != nil {
		t.Errorf("Error getting flow entries. Err: %v", err)
	}

	// verify dscp v4 flow
	dscpv4FlowMatch = fmt.Sprintf("priority=100,ip,in_port=14 actions=set_field:30->ip_dscp,write_metadata:0x100000000/0xff00000000")
	if agent.dpName == "vxlan" {
		dscpv4FlowMatch = fmt.Sprintf("priority=100,ip,in_port=14 actions=set_field:30->ip_dscp,push_vlan:0x8100,set_field:4097->vlan_vid,write_metadata:0x100000000/0xff00000000")
	}
	if !ofctlFlowMatch(flowList, VLAN_TBL_ID, dscpv4FlowMatch) {
		fmt.Printf("Flows:\n%v", strings.Join(flowList, "\n"))
		t.Fatalf("Could not find the flow %s on ovs %s", dscpv4FlowMatch, brName)
	}

	// verify dscp v6 flow
	dscpv6FlowMatch = fmt.Sprintf("priority=100,ipv6,in_port=14 actions=set_field:30->ip_dscp,write_metadata:0x100000000/0xff00000000")
	if agent.dpName == "vxlan" {
		dscpv6FlowMatch = fmt.Sprintf("priority=100,ipv6,in_port=14 actions=set_field:30->ip_dscp,push_vlan:0x8100,set_field:4097->vlan_vid,write_metadata:0x100000000/0xff00000000")
	}
	if !ofctlFlowMatch(flowList, VLAN_TBL_ID, dscpv6FlowMatch) {
		fmt.Printf("Flows:\n%v", strings.Join(flowList, "\n"))
		t.Fatalf("Could not find the flow %s on ovs %s", dscpv6FlowMatch, brName)
	}

	// remove the endpoint
	err = agent.RemoveLocalEndpoint(14)
	if err != nil {
		t.Fatalf("Error removing endpoint port %d. Err: %v", 14, err)
		return
	}

	// get the flow entries
	flowList, err = ofctlFlowDump(brName)
	if err != nil {
		t.Errorf("Error getting flow entries. Err: %v", err)
	}

	// verify port flow is removed
	portVlanFlowMatch = fmt.Sprintf("priority=10,in_port=14 actions=write_metadata:0x100000000/0xff00000000")
	if agent.dpName == "vxlan" {
		portVlanFlowMatch = fmt.Sprintf("priority=10,in_port=14 actions=push_vlan:0x8100,set_field:4097->vlan_vid,write_metadata:0x100000000/0xff00000000")
	}
	if ofctlFlowMatch(flowList, VLAN_TBL_ID, portVlanFlowMatch) {
		fmt.Printf("Flows:\n%v", strings.Join(flowList, "\n"))
		t.Fatalf("Flow %s is still present on ovs %s", portVlanFlowMatch, brName)
	}

	// verify dscp v4 flow is removed
	dscpv4FlowMatch = fmt.Sprintf("priority=100,ip,in_port=14 actions=set_field:30->ip_dscp,write_metadata:0x100000000/0xff00000000")
	if agent.dpName == "vxlan" {
		dscpv4FlowMatch = fmt.Sprintf("priority=100,ip,in_port=14 actions=set_field:30->ip_dscp,push_vlan:0x8100,set_field:4097->vlan_vid,write_metadata:0x100000000/0xff00000000")
	}
	if ofctlFlowMatch(flowList, VLAN_TBL_ID, dscpv4FlowMatch) {
		fmt.Printf("Flows:\n%v", strings.Join(flowList, "\n"))
		t.Fatalf("Flow %s is still present on ovs %s", dscpv4FlowMatch, brName)
	}

	// verify dscp v6 flow is removed
	dscpv6FlowMatch = fmt.Sprintf("priority=100,ipv6,in_port=14 actions=set_field:30->ip_dscp,write_metadata:0x100000000/0xff00000000")
	if agent.dpName == "vxlan" {
		dscpv6FlowMatch = fmt.Sprintf("priority=100,ipv6,in_port=14 actions=set_field:30->ip_dscp,push_vlan:0x8100,set_field:4097->vlan_vid,write_metadata:0x100000000/0xff00000000")
	}
	if ofctlFlowMatch(flowList, VLAN_TBL_ID, dscpv6FlowMatch) {
		fmt.Printf("Flows:\n%v", strings.Join(flowList, "\n"))
		t.Fatalf("Flow %s is still present on ovs %s", dscpv6FlowMatch, brName)
	}
}
