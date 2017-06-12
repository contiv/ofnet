package ofnet

import (
	"fmt"
	"net"
	"testing"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/ofnet/ofctrl"
)

// Verify if the flow entries are installed on vlan bridge
func TestVlanArpRedirectFlowEntry(t *testing.T) {
	var cfg OfnetGlobalConfig
	for i := 0; i < NUM_AGENT; i++ {
		brName := "vlanBridge" + fmt.Sprintf("%d", i)
		arpFlowMatch := fmt.Sprintf("priority=100,arp,arp_op=1 actions=CONTROLLER")

		// Verify ARP redirect entry in default mode (ArpProxy)
		flowList, err := ofctlFlowDump(brName)
		if err != nil {
			t.Errorf("Error getting flow entries. Err: %v", err)
		}
		if !ofctlFlowMatch(flowList, 0, arpFlowMatch) {
			t.Errorf("Could not find the route %s on ovs %s", arpFlowMatch, brName)
			return
		}
		log.Infof("Found arp redirect flow %s on ovs %s for arp ArpProxy", arpFlowMatch, brName)

		// Verify ARP redirect entry after changing to arp ArpFlood
		cfg.ArpMode = ArpFlood
		GetTestVlanAgent(i).GlobalConfigUpdate(cfg)
		flowList, err = ofctlFlowDump(brName)
		if err != nil {
			t.Errorf("Error getting flow entries. Err: %v", err)
		}
		if ofctlFlowMatch(flowList, 0, arpFlowMatch) {
			t.Errorf("ARP Flood mode should not have route %s on ovs %s", arpFlowMatch, brName)
			return
		}
		log.Infof("No arp redirect flow %s on ovs %s for arp ArpFlood", arpFlowMatch, brName)

		// Verify ARP redirect entry after changing back to arp ArpProxy
		cfg.ArpMode = ArpProxy
		GetTestVlanAgent(i).GlobalConfigUpdate(cfg)
		flowList, err = ofctlFlowDump(brName)
		if err != nil {
			t.Errorf("Error getting flow entries. Err: %v", err)
		}
		if !ofctlFlowMatch(flowList, 0, arpFlowMatch) {
			t.Errorf("Could not find the route %s on ovs %s", arpFlowMatch, brName)
			return
		}
		log.Infof("vlan arp redirect flow test successful")
	}
}

// Verify if the flow entries are installed on vlan bridge
func TestVxlanArpRedirectFlowEntry(t *testing.T) {
	var cfg OfnetGlobalConfig
	for i := 0; i < NUM_AGENT; i++ {
		brName := "vxlanBridge" + fmt.Sprintf("%d", i)
		arpFlowMatch := fmt.Sprintf("priority=100,arp,arp_op=1 actions=CONTROLLER")

		// Verify ARP redirect entry in default mode (ArpProxy)
		flowList, err := ofctlFlowDump(brName)
		if err != nil {
			t.Errorf("Error getting flow entries. Err: %v", err)
		}
		if !ofctlFlowMatch(flowList, 0, arpFlowMatch) {
			t.Errorf("Could not find the route %s on ovs %s", arpFlowMatch, brName)
			return
		}
		// Verify ARP redirect entry after changing to arp ArpFlood
		cfg.ArpMode = ArpFlood
		GetTestVxlanAgent(i).GlobalConfigUpdate(cfg)
		flowList, err = ofctlFlowDump(brName)
		if err != nil {
			t.Errorf("Error getting flow entries. Err: %v", err)
		}
		if ofctlFlowMatch(flowList, 0, arpFlowMatch) {
			t.Errorf("ARP Flood mode should not have route %s on ovs %s", arpFlowMatch, brName)
			return
		}
		// Verify ARP redirect entry after changing back to arp roxy
		cfg.ArpMode = ArpProxy
		GetTestVxlanAgent(i).GlobalConfigUpdate(cfg)
		flowList, err = ofctlFlowDump(brName)
		if err != nil {
			t.Errorf("Error getting flow entries. Err: %v", err)
		}
		if !ofctlFlowMatch(flowList, 0, arpFlowMatch) {
			t.Errorf("Could not find the route %s on ovs %s", arpFlowMatch, brName)
			return
		}
		log.Infof("vxlan arp redirect flow test successful")
	}
}

// verifyGARPstats waits and checks for number of GARPs sent
func verifyGARPstats(numGarpCycles int) bool {
	time.Sleep(GARP_EXPIRY_DELAY * time.Second)
	count := vlanAgents[0].getStats("GARPSent")
	return (count == uint64(numGarpCycles*GARPRepeats))
}

func vlanAddDelEP(epID, epgID int, add bool) error {
	macAddr, _ := net.ParseMAC(fmt.Sprintf("02:02:02:%02x:%02x:%02x", epID, epID, epID))
	ipAddr := net.ParseIP(fmt.Sprintf("10.11.%d.%d", epID, epID))
	endpoint := EndpointInfo{
		PortNo:            uint32(NUM_AGENT + epID),
		MacAddr:           macAddr,
		Vlan:              uint16(epgID),
		EndpointGroup:     epgID,
		EndpointGroupVlan: uint16(epgID),
		IpAddr:            ipAddr,
	}

	if add {
		return vlanAgents[0].AddLocalEndpoint(endpoint)
	}
	return vlanAgents[0].RemoveLocalEndpoint(uint32(NUM_AGENT + epID))
}

// TestOfnetVlanGARPInject verifies GARP injection
func TestOfnetVlanGArpInject(t *testing.T) {
	var resp bool

	err1 := vlanAgents[0].AddNetwork(uint16(5), uint32(5), "", "testVrf")
	err2 := vlanAgents[0].AddNetwork(uint16(6), uint32(6), "", "testVrf")

	if err1 != nil || err2 != nil {
		t.Errorf("Error adding vlan %v, %v", err1, err2)
		return
	}

	log.Infof("Testing GARP injection.. this might take a while")
	// =============== Endpoint Add/Del GARP test cases ================= //
	log.Infof("Adding one EP and checking GARPs")
	// Add one endpoint
	err := vlanAddDelEP(5, 5, true)
	if err != nil {
		t.Errorf("Error adding EP")
		return
	}

	time.Sleep(5 * time.Second)

	// Look for stats update
	count := vlanAgents[0].getStats("GARPSent")
	if count == 0 {
		t.Errorf("GARP stats wasn't updated ok: count: %v", count)
		return
	}

	// Add two endpoints to another epg
	log.Infof("Adding two more EPs and checking GARPs")
	vlanAddDelEP(6, 6, true)
	time.Sleep(GARP_EXPIRY_DELAY * time.Second)
	vlanAddDelEP(7, 6, true)
	if !verifyGARPstats(4) {
		t.Errorf("GARP stats incorrect count: %v exp: %v",
			count, 4*GARPRepeats)
		return
	}

	// delete one of the eps
	log.Infof("Deleting one EP and injecting GARPs")
	vlanAddDelEP(6, 6, false)
	vlanAgents[0].InjectGARPs(6, &resp)
	if !verifyGARPstats(5) {
		t.Errorf("GARP stats incorrect count: %v exp: %v",
			count, 5*GARPRepeats)
		return
	}
	// ============= Endpoint Add/Del GARP test cases end ============== //

	// =============== Bonded port GARP test cases ===================== //
	log.Infof("Creating uplink bonded port and checking GARPs")
	bondName := "uplinkBond"
	uplinkBond := createBondedPort(bondName, []string{"vvport300", "vvport301", "vvport302"})
	// Test link status triggered GARP
	err = addUplink(vlanAgents[0], uplinkBond)
	if err != nil {
		t.Fatal(err)
	}

	if !verifyGARPstats(7) {
		t.Errorf("GARP stats incorrect count: %v exp: %v",
			count, 7*GARPRepeats)
		return
	}

	// Flap one of the links in the bonded port and test that no GARPs are sent
	log.Infof("Flapping one of the links in the port and checking that GARPs are not sent")
	setLinkUpDown("vvport300", linkDown)
	time.Sleep(time.Second)
	setLinkUpDown("vvport300", linkUp)
	if !verifyGARPstats(7) {
		t.Errorf("GARP stats incorrect count: %v exp: %v",
			count, 7*GARPRepeats)
		return
	}

	// Flap all of the links in the bonded port and test that GARPs are sent
	log.Infof("Flapping all of the links in the port and checking that GARPs are sent")
	setLinkUpDown("vvport300", linkDown)
	setLinkUpDown("vvport301", linkDown)
	setLinkUpDown("vvport302", linkDown)
	time.Sleep(time.Second)
	setLinkUpDown("vvport300", linkUp)
	if !verifyGARPstats(9) {
		t.Errorf("GARP stats incorrect count: %v exp: %v",
			count, 9*GARPRepeats)
		return
	}
	setLinkUpDown("vvport301", linkUp)
	setLinkUpDown("vvport302", linkUp)
	if !verifyGARPstats(9) {
		t.Errorf("GARP stats incorrect count: %v exp: %v",
			count, 9*GARPRepeats)
		return
	}

	err = delUplink(vlanAgents[0], uplinkBond)
	if err != nil {
		t.Fatalf("Error deleting uplink. Err: %v", err)
	}
	// =============== Bonded port GARP test cases end ================== //

	// =============== Single interface GARP test cases ================== //
	log.Infof("Creating uplink port and checking GARPs")
	portName := "upPort"
	uplink := createPort(portName)
	// Test link status triggered GARP
	err = addUplink(vlanAgents[0], uplink)
	if err != nil {
		t.Fatal(err)
	}

	if !verifyGARPstats(11) {
		t.Errorf("GARP stats incorrect count: %v exp: %v",
			count, 11*GARPRepeats)
		return
	}

	// Flap the port and test that GARPs are sent
	log.Infof("Flapping the port and checking that GARPs are sent")
	setLinkUpDown(portName, linkDown)
	time.Sleep(time.Second)
	setLinkUpDown(portName, linkUp)
	if !verifyGARPstats(13) {
		t.Errorf("GARP stats incorrect count: %v exp: %v",
			count, 13*GARPRepeats)
		return
	}

	err = delUplink(vlanAgents[0], uplink)
	if err != nil {
		t.Fatalf("Error deleting uplink. Err: %v", err)
	}
	// =============== Single interface GARP test cases end ============== //

	vlanAddDelEP(7, 6, false)
	vlanAddDelEP(5, 5, false)
}

// addEndpoint adds an endpoint
func addEndpoint(ofa *OfnetAgent, portNo uint32, vlan uint16, macAddrStr, ipAddrStr string) error {
	macAddr, _ := net.ParseMAC(macAddrStr)
	endpoint := EndpointInfo{
		PortNo:            portNo,
		MacAddr:           macAddr,
		Vlan:              vlan,
		EndpointGroup:     0,
		EndpointGroupVlan: vlan,
		IpAddr:            net.ParseIP(ipAddrStr),
	}

	return ofa.AddLocalEndpoint(endpoint)
}

// injectArpReq injects an ARP request into ofnet
func injectArpReq(ofa *OfnetAgent, inPort, vlan int, macSrc, macDst, ipSrc, ipDst string) error {
	if macDst == "" {
		macDst = "ff:ff:ff:ff:ff:ff"
	}

	// inject an ARP request from ep1 for ep2
	arpReq := openflow13.NewPacketIn()
	arpReq.Match.Type = openflow13.MatchType_OXM
	arpReq.Match.AddField(*openflow13.NewInPortField(uint32(inPort)))
	arpReq.Data = *protocol.NewEthernet()
	arpReq.Data.Ethertype = protocol.ARP_MSG
	arpReq.Data.HWDst, _ = net.ParseMAC(macDst)
	arpReq.Data.HWSrc, _ = net.ParseMAC(macSrc)
	if vlan != 0 {
		arpReq.Data.VLANID.VID = uint16(vlan)
	}
	arpPkt, _ := protocol.NewARP(protocol.Type_Request)
	arpPkt.HWSrc, _ = net.ParseMAC(macSrc)
	arpPkt.IPSrc = net.ParseIP(ipSrc)
	arpPkt.HWDst, _ = net.ParseMAC("00:00:00:00:00:00")
	arpPkt.IPDst = net.ParseIP(ipDst)

	arpReq.Data.Data = arpPkt
	pkt := ofctrl.PacketIn(*arpReq)
	ofa.PacketRcvd(ofa.ofSwitch, &pkt)

	log.Debugf("Injected ARP request: %+v\n Packet: %+v", arpPkt, arpReq)
	return nil
}

// checkArpReqHandling injects ARP requests and checks expected count is incremented
func checkArpReqHandling(ofa *OfnetAgent, inPort, vlan int, macSrc, macDst, ipSrc, ipDst, expStat string, t *testing.T) {
	// get previous count
	prevCount := ofa.getStats(expStat)
	log.Debugf("BeforeStats: %+v", ofa.stats)

	// inject the packet
	err := injectArpReq(ofa, inPort, vlan, macSrc, macDst, ipSrc, ipDst)
	if err != nil {
		t.Fatalf("Error injecting ARP req. Err: %v", err)
	}

	log.Debugf("AfterStats: %+v", ofa.stats)
	newCount := ofa.getStats(expStat)
	if newCount != (prevCount + 1) {
		log.Infof("checkArpReqHandling: AfterStats: %+v", ofa.stats)
		t.Fatalf("%s value %d did not match expected value %d", expStat, newCount, (prevCount + 1))
	}
}

// TestVlanProxyArp tests proxy ARP in vlan mode
func TestVlanProxyArp(t *testing.T) {
	err := vlanAgents[0].AddNetwork(uint16(1), uint32(1), "", "test1")
	if err != nil {
		t.Errorf("Error adding vlan %v", err)
		return
	}

	// Add two endpoints
	err = addEndpoint(vlanAgents[0], 1, 1, "02:02:0A:01:01:01", "10.1.1.1")
	if err != nil {
		t.Errorf("Error adding endpoint")
		return
	}
	err = addEndpoint(vlanAgents[0], 2, 1, "02:02:0A:01:01:02", "10.1.1.2")
	if err != nil {
		t.Errorf("Error adding endpoint")
		return
	}
	err = addEndpoint(vlanAgents[1], 3, 1, "02:02:0A:01:01:03", "10.1.1.3")
	if err != nil {
		t.Errorf("Error adding endpoint")
		return
	}

	uplinkPort := createPort("uplinkPort")
	// add an uplink
	err = addUplink(vlanAgents[0], uplinkPort)
	if err != nil {
		t.Fatalf("Error adding uplink. Err: %v", err)
	}

	// Wait for link up
	time.Sleep(time.Second)

	// inject an ARP request from ep1 for ep2
	checkArpReqHandling(vlanAgents[0], 1, 0, "02:02:0A:01:01:01", "", "10.1.1.1", "10.1.1.2", "ArpReqRespSent", t)

	// inject a unicast ARP request from ep1 for ep2
	checkArpReqHandling(vlanAgents[0], 1, 0, "02:02:0A:01:01:01", "02:02:0A:01:01:02", "10.1.1.1", "10.1.1.2", "ArpReqRespSent", t)

	// inject ARP req from ep1 to unknown
	checkArpReqHandling(vlanAgents[0], 1, 0, "02:02:0A:01:01:01", "", "10.1.1.1", "10.1.1.254", "ArpReqReinject", t)

	// inject ARP req from uplink to local addr
	checkArpReqHandling(vlanAgents[0], int(uplinkPort.MbrLinks[0].OfPort), 1, "02:02:0A:01:01:FE", "", "10.1.1.254", "10.1.1.1", "ArpReqRespSent", t)

	// inject ARP req from uplink to unknown
	checkArpReqHandling(vlanAgents[0], int(uplinkPort.MbrLinks[0].OfPort), 1, "02:02:0A:01:01:FE", "", "10.1.1.254", "10.1.1.200", "ArpRequestUnknownSrcDst", t)

	// inject ARP req from uplink to unknown dest with known src
	checkArpReqHandling(vlanAgents[0], int(uplinkPort.MbrLinks[0].OfPort), 1, "02:02:0A:01:01:01", "", "10.1.1.1", "10.1.1.200", "ArpReqUnknownDestFromUplink", t)

	// inject ARP req from uplink to non-local dest
	checkArpReqHandling(vlanAgents[0], int(uplinkPort.MbrLinks[0].OfPort), 1, "02:02:0A:01:01:01", "", "10.1.1.1", "10.1.1.3", "ArpReqNonLocalDestFromUplink", t)

	// cleanup uplink
	err = delUplink(vlanAgents[0], uplinkPort)
	if err != nil {
		t.Fatalf("Error deleting uplink. Err: %v", err)
	}

	// cleanup endpoints
	err = vlanAgents[0].RemoveLocalEndpoint(1)
	if err != nil {
		t.Fatalf("Error deleting endpoint. Err: %v", err)
	}
	err = vlanAgents[0].RemoveLocalEndpoint(2)
	if err != nil {
		t.Fatalf("Error deleting endpoint. Err: %v", err)
	}
}

// TestVxlanProxyArp tests proxy ARP in vxlan mode
func TestVxlanProxyArp(t *testing.T) {
	err := vxlanAgents[0].AddNetwork(uint16(1), uint32(1), "", "test1")
	if err != nil {
		t.Errorf("Error adding vxlan %v", err)
		return
	}

	// Add two endpoints
	err = addEndpoint(vxlanAgents[0], 1, 1, "02:02:0A:01:01:01", "10.1.1.1")
	if err != nil {
		t.Errorf("Error adding endpoint")
		return
	}
	err = addEndpoint(vxlanAgents[0], 2, 1, "02:02:0A:01:01:02", "10.1.1.2")
	if err != nil {
		t.Errorf("Error adding endpoint")
		return
	}
	err = addEndpoint(vxlanAgents[1], 3, 1, "02:02:0A:01:01:03", "10.1.1.3")
	if err != nil {
		t.Errorf("Error adding endpoint")
		return
	}

	// add a vtep
	err = vxlanAgents[0].AddVtepPort(88, net.ParseIP("192.168.2.11"))
	if err != nil {
		t.Fatalf("Error adding VTEP. Err: %v", err)
	}

	// inject an ARP request from ep1 for ep2
	checkArpReqHandling(vxlanAgents[0], 1, 0, "02:02:0A:01:01:01", "", "10.1.1.1", "10.1.1.2", "ArpReqRespSent", t)

	// inject a unicast ARP request from ep1 for ep2
	checkArpReqHandling(vxlanAgents[0], 1, 0, "02:02:0A:01:01:01", "02:02:0A:01:01:02", "10.1.1.1", "10.1.1.2", "ArpReqRespSent", t)

	// inject ARP req from ep1 to unknown
	checkArpReqHandling(vxlanAgents[0], 1, 0, "02:02:0A:01:01:01", "", "10.1.1.1", "10.1.1.254", "ArpReqReinject", t)

	// inject ARP req from uplink to local addr
	checkArpReqHandling(vxlanAgents[0], 88, 1, "02:02:0A:01:01:FE", "", "10.1.1.254", "10.1.1.1", "ArpReqRespSent", t)

	// inject ARP req from uplink to unknown
	checkArpReqHandling(vxlanAgents[0], 88, 1, "02:02:0A:01:01:FE", "", "10.1.1.254", "10.1.1.200", "ArpRequestUnknownSrcDst", t)

	// inject ARP req from uplink to unknown dest with known src
	checkArpReqHandling(vxlanAgents[0], 88, 1, "02:02:0A:01:01:01", "", "10.1.1.1", "10.1.1.200", "ArpReqUnknownDestFromVtep", t)

	// inject ARP req from uplink to non-local dest
	checkArpReqHandling(vxlanAgents[0], 88, 1, "02:02:0A:01:01:01", "", "10.1.1.1", "10.1.1.3", "ArpReqNonLocalDestFromVtep", t)

	// cleanup vtep
	err = vxlanAgents[0].RemoveVtepPort(88, net.ParseIP("192.168.2.11"))
	if err != nil {
		t.Fatalf("Error deleting vtep. Err: %v", err)
	}

	// cleanup endpoints
	err = vxlanAgents[0].RemoveLocalEndpoint(1)
	if err != nil {
		t.Fatalf("Error deleting endpoint. Err: %v", err)
	}
	err = vxlanAgents[0].RemoveLocalEndpoint(2)
	if err != nil {
		t.Fatalf("Error deleting endpoint. Err: %v", err)
	}
}
