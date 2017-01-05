package ofnet

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

var gblOfPort = 1

func TestUplinkPortCreateDelete(t *testing.T) {
	uplinkSinglePort := createPort("upPort")
	uplinkBondedPort := createBondedPort("upBond", []string{"vvport311", "vvport312"})
	// Check uplink port creation in vlan bridge mode
	err := addUplink(vlanAgents[0], uplinkSinglePort)
	if err != nil {
		t.Fatalf("Uplink port creation failed for vlanagent: %+v", err)
	}

	err = delUplink(vlanAgents[0], uplinkSinglePort)
	if err != nil {
		t.Fatalf("Uplink port deletion failed for vlanagent: %+v", err)
	}

	// Check uplink bonded port creation in vlan bridge mode
	err = addUplink(vlanAgents[0], uplinkBondedPort)
	if err != nil {
		t.Fatalf("Uplink bonded port creation failed for vlanagent: %+v", err)
	}

	err = delUplink(vlanAgents[0], uplinkBondedPort)
	if err != nil {
		t.Fatalf("Uplink bonded port deletion failed for vlanagent: %+v", err)
	}

	// Check uplink port creation in vlrouter mode
	// In vlrouter mode, we currently support only one interface
	err = addUplink(vlrtrAgents[0], uplinkSinglePort)
	if err != nil {
		t.Fatalf("Uplink port creation failed for vlrouter agent: %+v", err)
	}

	err = delUplink(vlrtrAgents[0], uplinkSinglePort)
	if err != nil {
		t.Fatalf("Uplink port deletion failed for vlrouter agent: %+v", err)
	}

	// Check uplink bonded port creation in vlrouter mode
	err = addUplink(vlrtrAgents[0], uplinkBondedPort)
	if err == nil {
		t.Fatalf("Uplink port creation with multiple interfaces expected to fail for vlrouter agent: %+v", err)
	}
}

func TestPortActiveLinksStateChange(t *testing.T) {
	bondName := "upBond1"
	linkNames := []string{"vvport321", "vvport322", "vvport323", "vvport324", "vvport325"}
	uplinkBondedPort := createBondedPort(bondName, linkNames)

	err := addUplink(vlanAgents[0], uplinkBondedPort)
	if err != nil {
		t.Fatalf("Uplink bonded port creation failed for vlanagent: %+v", err)
	}

	defer delUplink(vlanAgents[0], uplinkBondedPort)

	vlanBr := vlanAgents[0].datapath.(*VlanBridge)
	vlanUplink := vlanBr.GetUplink(bondName)

	if len(linkNames) != len(vlanUplink.ActiveLinks) {
		t.Fatalf("Num active links not equal to num interfaces added.")
	}

	err = setLinkUpDown(linkNames[0], linkDown)
	if err != nil {
		t.Errorf("Error setting link down for %s", linkNames[0])
	}

	// Wait for a few seconds for Link messages to be triggered and processed
	time.Sleep(3 * time.Second)

	if len(vlanUplink.ActiveLinks) != 4 {
		t.Fatalf("Number of active links not updated after link down. %+v", vlanUplink)
	}

	// Check Active links on link bringup
	err = setLinkUpDown(linkNames[0], linkUp)
	if err != nil {
		t.Errorf("Error setting link up for %s", linkNames[0])
	}
	// Wait for a few seconds for Link messages to be triggered and processed
	time.Sleep(3 * time.Second)

	if len(linkNames) != len(vlanUplink.ActiveLinks) {
		t.Fatalf("Active links not updated after link bringup of %s", linkNames[0])
	}
}

func TestPortLACPStatusChange(t *testing.T) {
	bondName := "upBond1"
	linkNames := []string{"vvport321", "vvport322", "vvport323", "vvport324", "vvport325"}
	uplinkBondedPort := createBondedPort(bondName, linkNames)

	err := addUplink(vlanAgents[0], uplinkBondedPort)
	if err != nil {
		t.Fatalf("Uplink bonded port creation failed for vlanagent: %+v", err)
	}

	defer delUplink(vlanAgents[0], uplinkBondedPort)

	vlanBr := vlanAgents[0].datapath.(*VlanBridge)
	vlanUplink := vlanBr.GetUplink(bondName)

	if len(linkNames) != len(vlanUplink.ActiveLinks) {
		t.Fatalf("Num active links not equal to num interfaces added.")
	}

	// Check LACP Down event processing
	lacpDownUpd := LinkUpdateInfo{LinkName: linkNames[0], LacpStatus: false}
	portUpd := PortUpdate{UpdateType: LacpUpdate, UpdateInfo: lacpDownUpd}
	portUpds := PortUpdates{PortName: bondName, Updates: []PortUpdate{portUpd}}
	err = vlanAgents[0].UpdateUplink(uplinkBondedPort.Name, portUpds)
	if err != nil {
		t.Fatalf("Error processing update uplink. Err: %+v", err)
	}

	if len(linkNames)-1 != len(vlanUplink.ActiveLinks) {
		t.Fatalf("LACP down port update did not update active links")
	}

	// Check LACP Up event processing
	lacpUpUpd := LinkUpdateInfo{LinkName: linkNames[0], LacpStatus: true}
	portUpd = PortUpdate{UpdateType: LacpUpdate, UpdateInfo: lacpUpUpd}
	portUpds = PortUpdates{PortName: bondName, Updates: []PortUpdate{portUpd}}
	err = vlanAgents[0].UpdateUplink(uplinkBondedPort.Name, portUpds)
	if err != nil {
		t.Fatalf("Error processing update uplink. Err: %+v", err)
	}

	if len(linkNames) != len(vlanUplink.ActiveLinks) {
		t.Fatalf("LACP up port update did not update active links")
	}

	// Test multiple events
	link1Upd := PortUpdate{UpdateType: LacpUpdate, UpdateInfo: LinkUpdateInfo{LinkName: linkNames[0], LacpStatus: false}}
	link2Upd := PortUpdate{UpdateType: LacpUpdate, UpdateInfo: LinkUpdateInfo{LinkName: linkNames[1], LacpStatus: false}}
	link3Upd := PortUpdate{UpdateType: LacpUpdate, UpdateInfo: LinkUpdateInfo{LinkName: linkNames[2], LacpStatus: false}}
	portUpds = PortUpdates{PortName: bondName, Updates: []PortUpdate{link1Upd, link2Upd, link3Upd}}
	err = vlanAgents[0].UpdateUplink(uplinkBondedPort.Name, portUpds)
	if err != nil {
		t.Fatalf("Error processing update uplink. Err: %+v", err)
	}

	if len(linkNames)-3 != len(vlanUplink.ActiveLinks) {
		t.Fatalf("Mulitple LACP down port update did not update active links")
	}
}

func createPort(portName string) *PortInfo {
	var port PortInfo
	link := LinkInfo{
		Name:       portName,
		OfPort:     uint32(gblOfPort),
		LinkStatus: linkDown,
		Port:       &port,
	}

	port = PortInfo{
		Name:       portName,
		Type:       PortType,
		LinkStatus: linkDown,
		MbrLinks:   []*LinkInfo{&link},
	}

	gblOfPort++
	return &port
}

func createBondedPort(bondName string, linkNames []string) *PortInfo {
	var links []*LinkInfo
	var port PortInfo
	for i := 0; i < len(linkNames); i++ {
		link := &LinkInfo{
			Name:       linkNames[i],
			OfPort:     uint32(gblOfPort),
			LinkStatus: linkDown,
			Port:       &port,
		}
		links = append(links, link)
		gblOfPort++
	}

	port = PortInfo{
		Name:       bondName,
		Type:       BondType,
		LinkStatus: linkDown,
		MbrLinks:   links,
	}

	return &port
}

// setLinkUpDown sets the individual physical interface status up/down
func setLinkUpDown(linkName string, status linkStatus) error {
	var err error
	link := findLink(linkName)
	if link == nil {
		return fmt.Errorf("Could not find link: %s", linkName)
	}

	if status == linkUp {
		err = netlink.LinkSetUp(link)
	} else {
		err = netlink.LinkSetDown(link)
	}

	return err
}

// findLink finds the physical interface entity
func findLink(linkName string) netlink.Link {
	list, _ := netlink.LinkList()
	for _, l := range list {
		if strings.EqualFold(l.Attrs().Name, linkName) {
			return l
		}
	}
	return nil
}

// addUplink adds a dummy uplink to ofnet agent
func addUplink(ofa *OfnetAgent, uplinkPort *PortInfo) error {
	for _, link := range uplinkPort.MbrLinks {
		link := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name:   link.Name,
				TxQLen: 100,
				MTU:    1500,
			},
			PeerName: link.Name + "peer",
		}
		netlink.LinkDel(link)
		time.Sleep(100 * time.Millisecond)

		if err := netlink.LinkAdd(link); err != nil {
			return err
		}
	}

	time.Sleep(time.Second)

	// add it to ofnet
	err := ofa.AddUplink(uplinkPort)
	if err != nil {
		return err
	}

	for _, link := range uplinkPort.MbrLinks {
		setLinkUpDown(link.Name, linkUp)
	}

	time.Sleep(5 * time.Second)
	return nil
}

// delUplink deletes an uplink from ofnet agent
func delUplink(ofa *OfnetAgent, uplinkPort *PortInfo) error {
	err := ofa.RemoveUplink(uplinkPort.Name)
	if err != nil {
		return fmt.Errorf("Error deleting uplink. Err: %v", err)
	}

	for _, mbrLink := range uplinkPort.MbrLinks {
		link := findLink(mbrLink.Name)
		// cleanup the uplink
		if err := netlink.LinkDel(link); err != nil {
			return fmt.Errorf("Error deleting link: %v", err)
		}
	}

	return nil
}
