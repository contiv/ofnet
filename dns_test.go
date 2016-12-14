package ofnet

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/contiv/ofnet/ofctrl"
	"github.com/shaleman/libOpenflow/openflow13"
	"github.com/shaleman/libOpenflow/protocol"
	"net"
	"runtime"
	"strings"
	"testing"
)

func assertOnTrue(t *testing.T, val bool, msg string) {
	if val == true {
		t.Fatalf("Error %s", msg)
	}
}

func enterFunc() {
	if pc, _, _, ok := runtime.Caller(1); ok {
		log.Infof("=== enter %s() ====", runtime.FuncForPC(pc).Name())
	}
}

// checksum test
func TestChecksum(t *testing.T) {
	pkt := []byte{0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
		0xc0, 0xa8, 0x00, 0xc7,
	}
	s := ipChecksum(pkt)
	assertOnTrue(t, s != 0xB861, fmt.Sprintf("checksum failed got %0x", s))
}

// test DNS response packet
func TestDnsRespPkt(t *testing.T) {
	enterFunc()
	udpData := []byte{0x00, 0x02, 0x03, 0x5, 077, 0x78, 0xAF}
	ethPkt1 := protocol.NewEthernet()
	ethPkt1.HWDst = net.HardwareAddr{0x00, 0xA0, 0xF8, 0x08, 0x09, 0x0A}
	ethPkt1.HWSrc = net.HardwareAddr{0x00, 0xA0, 0xF8, 0x02, 0x03, 0x04}
	ethPkt1.Ethertype = protocol.IPv4_MSG
	ipPkt1 := protocol.NewIPv4()
	ethPkt1.Data = ipPkt1
	ipPkt1.Length = 100
	ipPkt1.FragmentOffset = 123
	ipPkt1.NWDst = net.IP{10, 1, 2, 3}
	ipPkt1.NWSrc = net.IP{100, 10, 1, 4}
	ipPkt1.Data = ethPkt1
	udpPkt1 := protocol.NewUDP()
	ipPkt1.Data = udpPkt1
	udpPkt1.PortDst = uint16(53)
	udpPkt1.PortSrc = uint16(6153)

	ethPkt2, err := buildUDPRespPkt(ethPkt1, udpData)
	assertOnTrue(t, err != nil, fmt.Sprintf("build udp response failed %s", err))
	assertOnTrue(t, len(ethPkt2.HWDst) != len(ethPkt1.HWDst), "dst mac length error")
	assertOnTrue(t, len(ethPkt2.HWSrc) != len(ethPkt1.HWSrc), "src mac length error")
	for i := 0; i < len(ethPkt1.HWDst); i++ {
		assertOnTrue(t, ethPkt2.HWSrc[i] != ethPkt1.HWDst[i], "src mac error")
	}
	for i := 0; i < len(ethPkt1.HWSrc); i++ {
		assertOnTrue(t, ethPkt2.HWDst[i] != ethPkt1.HWSrc[i], "dst mac error")
	}

	ipPkt2, ok1 := ethPkt2.Data.(*protocol.IPv4)
	assertOnTrue(t, ok1 == false, "invalid ipv4 pkt")
	assertOnTrue(t, ipPkt2.TTL != 64, "invalid ttl")
	assertOnTrue(t, len(ipPkt2.NWDst) != len(ipPkt1.NWDst), "dst ip length error")
	assertOnTrue(t, len(ipPkt2.NWSrc) != len(ipPkt1.NWSrc), "src ip length error")
	for i := 0; i < len(ipPkt1.NWDst); i++ {
		assertOnTrue(t, ipPkt2.NWSrc[i] != ipPkt1.NWDst[i], "src ip error")
		assertOnTrue(t, ipPkt2.NWDst[i] != ipPkt1.NWSrc[i], "dst ip error")
	}
	udpPkt2, ok2 := ipPkt2.Data.(*protocol.UDP)
	assertOnTrue(t, ok2 == false, "invalid udp pkt")
	assertOnTrue(t, udpPkt2.PortSrc != udpPkt1.PortDst, "src udp port error")
	assertOnTrue(t, udpPkt2.PortDst != udpPkt1.PortSrc, "dest udp port error")
}

// test DNS forward packet
func TestDnsFwdPkt(t *testing.T) {
	enterFunc()
	ethPkt := protocol.NewEthernet()
	ethPkt.HWDst = net.HardwareAddr{0x00, 0xA0, 0xF8, 0x08, 0x09, 0x0A}
	ethPkt.HWSrc = net.HardwareAddr{0x00, 0xA0, 0xF8, 0x02, 0x03, 0x04}
	ethPkt.Ethertype = protocol.IPv4_MSG
	ethPkt.Data = new(protocol.IPv4)
	outPkt := buildDnsForwardPkt(ethPkt)
	assertOnTrue(t, outPkt.VLANID.VID != 4093, "vlan tag error")
	assertOnTrue(t, len(outPkt.HWDst) != len(ethPkt.HWDst), "dst mac length error")
	assertOnTrue(t, len(outPkt.HWSrc) != len(ethPkt.HWSrc), "src mac length error")
	for i := 0; i < len(ethPkt.HWDst); i++ {
		assertOnTrue(t, outPkt.HWDst[i] != ethPkt.HWDst[i], "dst mac error")
		assertOnTrue(t, outPkt.HWSrc[i] != ethPkt.HWSrc[i], "src mac error")
	}
	assertOnTrue(t, outPkt.Ethertype != ethPkt.Ethertype, "ether type error")
	assertOnTrue(t, outPkt.Data != ethPkt.Data, "ipv4 data error")
}

func verifyFlow(t *testing.T, brName string, flow string, flowExist bool) {
	flowList, err := ofctlFlowDump(brName)
	assertOnTrue(t, err != nil, fmt.Sprintf("failed to get flows, %s", err))
	assertOnTrue(t, ofctlFlowMatch(flowList, 0, flow) != flowExist,
		fmt.Sprintf("[%s]failed to find [%s] in [%v]", brName, flow, strings.Join(flowList, "\n")))
}

func sendDnsPkt(t *testing.T, agent *OfnetAgent, inPort int32, vlan uint16) {
	dnsReq := openflow13.NewPacketIn()
	dnsReq.Match.Type = openflow13.MatchType_OXM
	dnsReq.Match.AddField(*openflow13.NewInPortField(uint32(inPort)))
	dnsReq.Data = *protocol.NewEthernet()
	dnsReq.Data.Ethertype = protocol.IPv4_MSG
	dnsReq.Data.HWDst = net.HardwareAddr{02, 02, 02, 05, 05, 05}
	dnsReq.Data.HWSrc = net.HardwareAddr{02, 02, 02, 06, 06, 06}
	if vlan != 0 {
		dnsReq.Data.VLANID.VID = vlan
	} else {
		vlan = 12
	}

	ipPkt := protocol.NewIPv4()
	dnsReq.Data.Data = ipPkt
	ipPkt.NWDst = net.IP{10, 192, 10, 11}
	ipPkt.NWSrc = net.IP{11, 192, 10, 31}
	ipPkt.Protocol = protocol.Type_UDP
	udpPkt := protocol.NewUDP()
	ipPkt.Data = udpPkt
	udpPkt.PortDst = 53
	udpPkt.PortSrc = 1153
	udpPkt.Data = []byte{1, 2, 3, 4}

	pkt := ofctrl.PacketIn(*dnsReq)
	agent.portVlanMap[uint32(inPort)] = &vlan
	tenant := "ten1001"
	agent.vlanVrf[uint16(vlan)] = &tenant
	agent.PacketRcvd(agent.ofSwitch, &pkt)
}

func testOfnetDnsUplinkFlow(t *testing.T) {
	testList := []struct {
		agent  *OfnetAgent
		brName string
	}{
		{vrtrAgents[0], "vrtrBridge0"},
		{vxlanAgents[0], "vxlanBridge0"},
		{vlanAgents[0], "vlanBridge0"},
		{vlrtrAgents[0], "vlrtrBridge0"},
	}

	for _, l := range testList {
		agent := l.agent
		brName := l.brName

		switch agent.dpName {
		case "vxlan", "vrouter":
			err := agent.datapath.AddVtepPort(uint32(101), net.ParseIP("10.36.1.101"))
			assertOnTrue(t, err != nil, fmt.Sprintf("failed to add vtep port: 101, %s", err))
			flow := fmt.Sprintf("priority=102,udp,in_port=101,tp_dst=53 actions=goto_table:1")
			verifyFlow(t, brName, flow, true)

			err = agent.datapath.RemoveVtepPort(uint32(101), net.ParseIP("10.36.1.101"))
			assertOnTrue(t, err != nil, fmt.Sprintf("failed to delete vtep port: 101, %s", err))
			verifyFlow(t, brName, flow, false)

		case "vlan", "vlrouter":
			link := LinkInfo{
				Name:       "uplink101",
				OfPort:     uint32(101),
				LinkStatus: linkDown,
				Port:       new(PortInfo),
			}

			port := PortInfo{
				Name:       "uplink101",
				Type:       PortType,
				LinkStatus: linkDown,
				MbrLinks:   []*LinkInfo{&link},
			}

			err := addUplink(agent, &port)
			assertOnTrue(t, err != nil, fmt.Sprintf("failed to add uplink port: 101, %s", err))
			flow := fmt.Sprintf("priority=102,udp,in_port=101,tp_dst=53 actions=goto_table:1")
			verifyFlow(t, brName, flow, true)

			err = delUplink(agent, &port)
			assertOnTrue(t, err != nil, fmt.Sprintf("failed to delete uplink port: 101, %s", err))
			verifyFlow(t, brName, flow, false)

			if agent.dpName == "vlan" {
				link := []LinkInfo{{
					Name:       "uplink101",
					OfPort:     uint32(101),
					LinkStatus: linkDown,
					Port:       new(PortInfo),
				},
					{
						Name:       "uplink102",
						OfPort:     uint32(102),
						LinkStatus: linkDown,
						Port:       new(PortInfo),
					},
				}

				port := PortInfo{
					Name:       "uplink101",
					Type:       PortType,
					LinkStatus: linkDown,
					MbrLinks:   []*LinkInfo{&link[0], &link[1]},
				}

				err := addUplink(agent, &port)
				assertOnTrue(t, err != nil, fmt.Sprintf("failed to add uplink port: 101, %s", err))
				flow1 := fmt.Sprintf("priority=102,udp,in_port=101,tp_dst=53 actions=goto_table:1")
				flow2 := fmt.Sprintf("priority=102,udp,in_port=102,tp_dst=53 actions=goto_table:1")
				verifyFlow(t, brName, flow1, true)
				verifyFlow(t, brName, flow2, true)

				err = delUplink(agent, &port)
				assertOnTrue(t, err != nil, fmt.Sprintf("failed to delete uplink port: 101, %s", err))
				verifyFlow(t, brName, flow1, false)
				verifyFlow(t, brName, flow2, false)
			}

		}
	}
}

func testOfnetDnsInitFlow(t *testing.T) {
	testList := []string{
		"vrtrBridge0",
		"vxlanBridge0",
		"vlanBridge0",
		"vlrtrBridge0",
	}

	flow1 := fmt.Sprintf("priority=100,udp,dl_src=02:02:00:00:00:00/ff:ff:00:00:00:00,tp_dst=53 actions=CONTROLLER:65535")
	flow2 := fmt.Sprintf("priority=101,udp,dl_vlan=4093,dl_src=02:02:00:00:00:00/ff:ff:00:00:00:00,tp_dst=53 actions=pop_vlan,goto_table:1")

	for _, brName := range testList {
		flowList, err := ofctlFlowDump(brName)
		assertOnTrue(t, err != nil, fmt.Sprintf("Error getting flow entries. Err: %v", err))

		assertOnTrue(t, ofctlFlowMatch(flowList, 0, flow1) != true,
			fmt.Sprintf("[%s]failed to find [%s] in [%v]", brName, flow1, strings.Join(flowList, "\n")))
		assertOnTrue(t, ofctlFlowMatch(flowList, 0, flow2) != true,
			fmt.Sprintf("[%s]failed to find [%s] in [%v]", brName, flow2, strings.Join(flowList, "\n")))
	}
}

type dls1 struct {
	dummy int
}

func (dl *dls1) NsLookup([]byte, *string) ([]byte, error) {
	return []byte{1, 2, 3, 4}, nil
}

type dlf1 struct {
	dummy int
}

func (dl *dlf1) NsLookup([]byte, *string) ([]byte, error) {
	return []byte{1, 2, 3, 4}, fmt.Errorf("")
}

type edns1 struct {
	dummy int
}

func (dl *edns1) NsLookup([]byte, *string) ([]byte, error) {
	a := [1500]byte{}
	return a[0:], nil
}

func TestDnsLookup(t *testing.T) {
	testList := []struct {
		agent  *OfnetAgent
		brName string
	}{
		{vrtrAgents[0], "vrtrBridge0"},
		{vxlanAgents[0], "vxlanBridge0"},
		{vlanAgents[0], "vlanBridge0"},
		{vlrtrAgents[0], "vlrtrBridge0"},
	}

	for _, l := range testList {
		agent := l.agent
		log.Infof("processing :%s", l.brName)
		agent.AddNameServer(new(dls1))
		delete(agent.stats, "dnsPktReply")
		sendDnsPkt(t, agent, 12, uint16(0))
		s := agent.stats["dnsPktReply"]
		assertOnTrue(t, s != 1, fmt.Sprintf("[%s] reply-stats didnt match %+v", l.brName, agent.stats))

		agent.AddNameServer(new(dlf1))
		delete(agent.stats, "dnsPktForward")
		sendDnsPkt(t, agent, 12, uint16(0))
		s = agent.stats["dnsPktForward"]
		assertOnTrue(t, s != 1, fmt.Sprintf("[%s] fwd-stats didnt match %+v ", l.brName, agent.stats))

		// check length of resp.
		agent.AddNameServer(new(edns1))
		delete(agent.stats, "dnsPktForward")
		sendDnsPkt(t, agent, 12, uint16(0))
		s = agent.stats["dnsPktForward"]
		assertOnTrue(t, s != 1,
			fmt.Sprintf("[%s] pkts > 1024 should be ignored, fwd-stats didnt match %+v ",
				l.brName, agent.stats))

	}
}

// test dns flows
func TestDnsFlows(t *testing.T) {
	enterFunc()
	testOfnetDnsInitFlow(t)
	testOfnetDnsUplinkFlow(t)
}
