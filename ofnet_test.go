package ofnet

// Test ofnet APIs

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/contiv/ofnet/ovsdbDriver"

	log "github.com/Sirupsen/logrus"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const NUM_MASTER = 2
const NUM_AGENT = 3
const NUM_ITER = 2

/* NOTE:
 * Currently only one vlrouter Master is supported
 * Change this once the support for multiple masters comes in
 */
const NUM_VLRTR_MASTER = 1
const NUM_VLRTR_AGENT = 1

// Port constants
const VRTR_MASTER_PORT = 9101
const VRTR_RPC_PORT = 9121
const VRTR_OVS_PORT = 9151
const VXLAN_MASTER_PORT = 9201
const VXLAN_RPC_PORT = 9221
const VXLAN_OVS_PORT = 9251
const VLAN_MASTER_PORT = 9301
const VLAN_RPC_PORT = 9321
const VLAN_OVS_PORT = 9351
const VLRTR_MASTER_PORT = 9401
const VLRTR_RPC_PORT = 9421
const VLRTR_OVS_PORT = 9451

var vrtrMasters [NUM_MASTER]*OfnetMaster
var vxlanMasters [NUM_MASTER]*OfnetMaster
var vlanMasters [NUM_MASTER]*OfnetMaster
var vlrtrMaster [NUM_VLRTR_MASTER]*OfnetMaster
var vrtrAgents [NUM_AGENT]*OfnetAgent
var vxlanAgents [NUM_AGENT]*OfnetAgent
var vlanAgents [NUM_AGENT]*OfnetAgent
var vlrtrAgents [NUM_VLRTR_AGENT]*OfnetAgent
var ovsDrivers [(3 * NUM_AGENT) + NUM_VLRTR_AGENT]*ovsdbDriver.OvsDriver

var localIpList []string

// Create couple of ofnet masters and few agents
func TestMain(m *testing.M) {
	var err error

	for i := 0; i < NUM_AGENT; i++ {
		localIpList = append(localIpList, fmt.Sprintf("10.10.10.%d", (i+1)))
	}

	// Create the masters
	for i := 0; i < NUM_MASTER; i++ {
		vrtrMasters[i] = NewOfnetMaster("", uint16(VRTR_MASTER_PORT+i))
		if vrtrMasters[i] == nil {
			log.Fatalf("Error creating ofnet master for vrouter: %d", i)
		}

		log.Infof("Created vrouter Master: %v", vrtrMasters[i])

		vxlanMasters[i] = NewOfnetMaster("", uint16(VXLAN_MASTER_PORT+i))
		if vxlanMasters[i] == nil {
			log.Fatalf("Error creating ofnet master for vxlan: %d", i)
		}

		log.Infof("Created vxlan Master: %v", vxlanMasters[i])

		vlanMasters[i] = NewOfnetMaster("", uint16(VLAN_MASTER_PORT+i))
		if vlanMasters[i] == nil {
			log.Fatalf("Error creating ofnet master for vlan: %d", i)
		}

		log.Infof("Created vlan Master: %v", vlanMasters[i])
	}

	for i := 0; i < NUM_VLRTR_MASTER; i++ {
		vlrtrMaster[i] = NewOfnetMaster("", uint16(VLRTR_MASTER_PORT))
		if vlrtrMaster[i] == nil {
			log.Fatalf("Error creating ofnet master for vlrtr: %d", i)
		}

		log.Infof("Created vlrtr Master: %v", vlrtrMaster[i])
	}

	// Wait a second for masters to be up
	time.Sleep(1 * time.Second)

	// Create agents
	for i := 0; i < NUM_AGENT; i++ {
		brName := "vrtrBridge" + fmt.Sprintf("%d", i)
		rpcPort := uint16(VRTR_RPC_PORT + i)
		ovsPort := uint16(VRTR_OVS_PORT + i)
		lclIp := net.ParseIP(localIpList[i])
		vrtrAgents[i], err = NewOfnetAgent(brName, "vrouter", lclIp, rpcPort, ovsPort)
		if err != nil {
			log.Fatalf("Error creating ofnet agent. Err: %v", err)
		}

		// Override MyAddr to local host
		vrtrAgents[i].MyAddr = "127.0.0.1"

		log.Infof("Created vrouter ofnet agent: %v", vrtrAgents[i])
	}

	for i := 0; i < NUM_AGENT; i++ {
		brName := "vxlanBridge" + fmt.Sprintf("%d", i)
		rpcPort := uint16(VXLAN_RPC_PORT + i)
		ovsPort := uint16(VXLAN_OVS_PORT + i)
		lclIp := net.ParseIP(localIpList[i])

		vxlanAgents[i], err = NewOfnetAgent(brName, "vxlan", lclIp, rpcPort, ovsPort)
		if err != nil {
			log.Fatalf("Error creating ofnet agent. Err: %v", err)
		}

		// Override MyAddr to local host
		vxlanAgents[i].MyAddr = "127.0.0.1"

		log.Infof("Created vxlan ofnet agent: %v", vxlanAgents[i])
	}

	for i := 0; i < NUM_AGENT; i++ {
		brName := "vlanBridge" + fmt.Sprintf("%d", i)
		rpcPort := uint16(VLAN_RPC_PORT + i)
		ovsPort := uint16(VLAN_OVS_PORT + i)
		lclIp := net.ParseIP(localIpList[i])

		vlanAgents[i], err = NewOfnetAgent(brName, "vlan", lclIp, rpcPort, ovsPort)
		if err != nil {
			log.Fatalf("Error creating ofnet agent. Err: %v", err)
		}

		// Override MyAddr to local host
		vlanAgents[i].MyAddr = "127.0.0.1"

		log.Infof("Created vlan ofnet agent: %v", vlanAgents[i])
	}

	for i := 0; i < NUM_VLRTR_AGENT; i++ {
		brName := "vlrtrBridge" + fmt.Sprintf("%d", i)
		rpcPort := uint16(VLRTR_RPC_PORT + i)
		ovsPort := uint16(VLRTR_OVS_PORT + i)
		lclIp := net.ParseIP(localIpList[i])
		portName := "inb0" + fmt.Sprintf("%d", i)
		driver := ovsdbDriver.NewOvsDriver(brName)
		driver.CreatePort(portName, "internal", uint(1+i))
		vlrtrAgents[i], err = NewOfnetAgent(brName, "vlrouter", lclIp, rpcPort, ovsPort, portName)
		if err != nil {
			log.Fatalf("Error creating ofnet agent. Err: %v", err)
		}

		// Override MyAddr to local host
		vlrtrAgents[i].MyAddr = "127.0.0.1"

		log.Infof("Created vlrtr ofnet agent: %v", vlrtrAgents[i])
	}

	masterInfo := OfnetNode{
		HostAddr: "127.0.0.1",
	}

	var resp bool

	// Add master node to each agent
	for i := 0; i < NUM_AGENT; i++ {
		// add the two master nodes
		for j := 0; j < NUM_MASTER; j++ {
			masterInfo.HostPort = uint16(VRTR_MASTER_PORT + j)
			// connect vrtr agent to vrtr master
			err := vrtrAgents[i].AddMaster(&masterInfo, &resp)
			if err != nil {
				log.Fatalf("Error adding master %+v to vrtr node %d. Err: %v", masterInfo, i, err)
			}

			// connect vxlan agents to vxlan master
			masterInfo.HostPort = uint16(VXLAN_MASTER_PORT + j)
			err = vxlanAgents[i].AddMaster(&masterInfo, &resp)
			if err != nil {
				log.Fatalf("Error adding master %+v to vxlan node %d. Err: %v", masterInfo, i, err)
			}

			// connect vlan agents to vlan master
			masterInfo.HostPort = uint16(VLAN_MASTER_PORT + j)
			err = vlanAgents[i].AddMaster(&masterInfo, &resp)
			if err != nil {
				log.Fatalf("Error adding master %+v to vlan node %d. Err: %v", masterInfo, i, err)
			}
		}
	}

	for i := 0; i < NUM_VLRTR_AGENT; i++ {
		for j := 0; j < NUM_VLRTR_MASTER; j++ {
			// connect vlrtr agents to vlrtr master
			masterInfo.HostPort = uint16(VLRTR_MASTER_PORT + j)
			err = vlrtrAgents[i].AddMaster(&masterInfo, &resp)
			if err != nil {
				log.Fatalf("Error adding master %+v to vlrtr node %d. Err: %v", masterInfo, i, err)
			}

		}
	}

	log.Infof("Ofnet masters and agents are setup..")

	time.Sleep(1 * time.Second)
	for i := 0; i < NUM_MASTER; i++ {
		err := vrtrMasters[i].MakeDummyRpcCall()
		if err != nil {
			log.Fatalf("Error making dummy rpc call. Err: %v", err)
			return
		}
		err = vxlanMasters[i].MakeDummyRpcCall()
		if err != nil {
			log.Fatalf("Error making dummy rpc call. Err: %v", err)
			return
		}
		err = vlanMasters[i].MakeDummyRpcCall()
		if err != nil {
			log.Fatalf("Error making dummy rpc call. Err: %v", err)
			return
		}
	}
	for i := 0; i < NUM_VLRTR_MASTER; i++ {
		err = vlrtrMaster[i].MakeDummyRpcCall()
		if err != nil {
			log.Fatalf("Error making dummy rpc call. Err: %v", err)
			return
		}
	}

	log.Infof("Made dummy rpc call to all agents")

	// Create OVS switches and connect them to vrouter ofnet agents
	for i := 0; i < NUM_AGENT; i++ {
		brName := "vrtrBridge" + fmt.Sprintf("%d", i)
		ovsPort := uint16(VRTR_OVS_PORT + i)
		ovsDrivers[i] = ovsdbDriver.NewOvsDriver(brName)
		err := ovsDrivers[i].AddController("127.0.0.1", ovsPort)
		if err != nil {
			log.Fatalf("Error adding controller to ovs: %s", brName)
		}
	}
	// Create OVS switches and connect them to vxlan ofnet agents
	for i := 0; i < NUM_AGENT; i++ {
		brName := "vxlanBridge" + fmt.Sprintf("%d", i)
		ovsPort := uint16(VXLAN_OVS_PORT + i)
		j := NUM_AGENT + i
		ovsDrivers[j] = ovsdbDriver.NewOvsDriver(brName)
		err := ovsDrivers[j].AddController("127.0.0.1", ovsPort)
		if err != nil {
			log.Fatalf("Error adding controller to ovs: %s", brName)
		}
	}

	// Create OVS switches and connect them to vlan ofnet agents
	for i := 0; i < NUM_AGENT; i++ {
		brName := "vlanBridge" + fmt.Sprintf("%d", i)
		ovsPort := uint16(VLAN_OVS_PORT + i)
		j := (2 * NUM_AGENT) + i
		ovsDrivers[j] = ovsdbDriver.NewOvsDriver(brName)
		err := ovsDrivers[j].AddController("127.0.0.1", ovsPort)
		if err != nil {
			log.Fatalf("Error adding controller to ovs: %s", brName)
		}
	}

	// Create OVS switches and connect them to vxlan ofnet agents
	for i := 0; i < NUM_VLRTR_AGENT; i++ {
		brName := "vlrtrBridge" + fmt.Sprintf("%d", i)
		ovsPort := uint16(VLRTR_OVS_PORT + i)
		j := (3 * NUM_AGENT) + i
		ovsDrivers[j] = ovsdbDriver.NewOvsDriver(brName)
		err := ovsDrivers[j].AddController("127.0.0.1", ovsPort)
		if err != nil {
			log.Fatalf("Error adding controller to ovs: %s", brName)
		}
	}

	// Wait for 20sec for switch to connect to controller
	time.Sleep(10 * time.Second)

	err = SetupVlans()
	if err != nil {
		log.Fatalf("Error setting up Vlans")
	}
	err = SetupVteps()
	if err != nil {
		log.Fatalf("Error setting up vteps")
	}

	// run the test
	exitCode := m.Run()
	os.Exit(exitCode)

}

// test adding vlan
func SetupVlans() error {
	for i := 0; i < NUM_AGENT; i++ {
		log.Info("Index %d \n", i)
		for j := 1; j < 5; j++ {
			log.Info("Index %d \n", j)
			//log.Infof("Adding Vlan %d on %s", j, localIpList[i])
			err := vrtrAgents[i].AddNetwork(uint16(j), uint32(j), "", "tenant1")
			if err != nil {
				log.Errorf("Error adding vlan %d to vrtrAgent. Err: %v", j, err)
				return err
			}
			err = vxlanAgents[i].AddNetwork(uint16(j), uint32(j), "", "default")
			if err != nil {
				log.Errorf("Error adding vlan %d to vxlanAgent. Err: %v", j, err)
				return err
			}
			err = vlanAgents[i].AddNetwork(uint16(j), uint32(j), "", "default")
			if err != nil {
				log.Errorf("Error adding vlan %d to vlanAgent. Err: %v", j, err)
				return err
			}
		}
	}
	for i := 0; i < NUM_VLRTR_AGENT; i++ {
		err := vlrtrAgents[i].AddNetwork(uint16(1), uint32(1),
			fmt.Sprintf("10.10.%d.%d", 1, 1), "default")
		if err != nil {
			log.Errorf("Error adding vlan 1 to vlrtrAgent. Err: %v", err)
			return err
		}
	}
	return nil
}

// test adding full mesh vtep ports
func SetupVteps() error {
	for i := 0; i < NUM_AGENT; i++ {
		for j := 0; j < NUM_AGENT; j++ {
			if i != j {
				log.Infof("Adding VTEP on %s for remoteIp: %s", localIpList[i], localIpList[j])
				err := vrtrAgents[i].AddVtepPort(uint32(j+1), net.ParseIP(localIpList[j]))
				if err != nil {
					log.Errorf("Error adding VTEP port. Err: %v", err)
					return err
				}
				err = vxlanAgents[i].AddVtepPort(uint32(j+1), net.ParseIP(localIpList[j]))
				if err != nil {
					log.Errorf("Error adding VTEP port. Err: %v", err)
					return err
				}
			}
		}
	}
	log.Infof("Finished setting up VTEP ports..")
	return nil
}

// Test adding/deleting Vrouter routes
func TestOfnetVrouteAddDelete(t *testing.T) {
	for iter := 0; iter < NUM_ITER; iter++ {
		for i := 0; i < NUM_AGENT; i++ {
			j := i + 1
			macAddr, _ := net.ParseMAC(fmt.Sprintf("02:02:02:%02x:%02x:%02x", j, j, j))
			ipAddr := net.ParseIP(fmt.Sprintf("10.10.%d.%d", j, j))
			var ipv6Addr net.IP
			if j%2 == 0 {
				ipv6Addr = net.ParseIP(fmt.Sprintf("2016::%d:%d", j, j))
			}
			endpoint := EndpointInfo{
				PortNo:   uint32(NUM_AGENT + 2),
				MacAddr:  macAddr,
				Vlan:     1,
				IpAddr:   ipAddr,
				Ipv6Addr: ipv6Addr,
			}

			log.Infof("Installing local vrouter endpoint: %+v", endpoint)

			// Install the local endpoint
			err := vrtrAgents[i].AddLocalEndpoint(endpoint)
			if err != nil {
				t.Fatalf("Error installing endpoint: %+v. Err: %v", endpoint, err)
				return
			}
		}

		log.Infof("Finished adding local vrouter endpoint")

		// verify all ovs switches have this route
		for i := 0; i < NUM_AGENT; i++ {
			brName := "vrtrBridge" + fmt.Sprintf("%d", i)

			flowList, err := ofctlFlowDump(brName)
			if err != nil {
				t.Errorf("Error getting flow entries. Err: %v", err)
			}
			// verify flow entry exists
			for j := 0; j < NUM_AGENT; j++ {
				k := j + 1
				ipFlowMatch := fmt.Sprintf("priority=100,ip,metadata=0x100000000/0xff00000000,nw_dst=10.10.%d.%d", k, k)
				ipTableId := IP_TBL_ID
				if !ofctlFlowMatch(flowList, ipTableId, ipFlowMatch) {
					t.Errorf("Could not find the route %s on ovs %s", ipFlowMatch, brName)
				}
				log.Infof("Found ipflow %s on ovs %s", ipFlowMatch, brName)

				if k%2 == 0 {
					ipv6FlowMatch := fmt.Sprintf("priority=100,ipv6,metadata=0x100000000/0xff00000000,ipv6_dst=2016::%d:%d", k, k)
					if !ofctlFlowMatch(flowList, ipTableId, ipv6FlowMatch) {
						t.Errorf("Could not find IPv6 route %s on ovs %s", ipv6FlowMatch, brName)
						return
					}
					log.Infof("Found IPv6 ipflow %s on ovs %s", ipv6FlowMatch, brName)
				}
			}
		}

		log.Infof("Adding Vrouter endpoint successful.\n Testing Delete")

		for i := 0; i < NUM_AGENT; i++ {
			j := i + 1
			macAddr, _ := net.ParseMAC(fmt.Sprintf("02:02:02:%02x:%02x:%02x", j, j, j))
			ipAddr := net.ParseIP(fmt.Sprintf("10.10.%d.%d", j, j))
			var ipv6Addr net.IP
			if j%2 == 0 {
				ipv6Addr = net.ParseIP(fmt.Sprintf("2016::%d:%d", j, j))
			}
			endpoint := EndpointInfo{
				PortNo:   uint32(NUM_AGENT + 2),
				MacAddr:  macAddr,
				Vlan:     1,
				IpAddr:   ipAddr,
				Ipv6Addr: ipv6Addr,
			}

			log.Infof("Deleting local vrouter endpoint: %+v", endpoint)

			// Install the local endpoint
			err := vrtrAgents[i].RemoveLocalEndpoint(uint32(NUM_AGENT + 2))
			if err != nil {
				t.Fatalf("Error deleting endpoint: %+v. Err: %v", endpoint, err)
				return
			}
		}

		log.Infof("Deleted endpoints. Verifying they are gone")

		// verify flows are deleted
		for i := 0; i < NUM_AGENT; i++ {
			brName := "vrtrBridge" + fmt.Sprintf("%d", i)

			flowList, err := ofctlFlowDump(brName)
			if err != nil {
				t.Errorf("Error getting flow entries. Err: %v", err)
			}
			// verify flow entry exists
			for j := 0; j < NUM_AGENT; j++ {
				k := j + 1
				ipFlowMatch := fmt.Sprintf("priority=100,ip,metadata=0x100000000/0xff00000000,nw_dst=10.10.%d.%d", k, k)
				ipTableId := IP_TBL_ID
				if ofctlFlowMatch(flowList, ipTableId, ipFlowMatch) {
					t.Errorf("Still found the flow %s on ovs %s", ipFlowMatch, brName)
				}
				if k%2 == 0 {
					ipv6FlowMatch := fmt.Sprintf("priority=100,ipv6,metadata=0x100000000/0xff00000000,ipv6_dst=2016::%d:%d", k, k)
					if ofctlFlowMatch(flowList, ipTableId, ipv6FlowMatch) {
						t.Errorf("Still found the flow %s on ovs %s", ipv6FlowMatch, brName)
					}
				}
			}
		}

		log.Infof("Verified all flows are deleted")
	}
}

// Test adding/deleting Vxlan routes
func TestOfnetVxlanAddDelete(t *testing.T) {
	for iter := 0; iter < NUM_ITER; iter++ {
		for i := 0; i < NUM_AGENT; i++ {
			j := i + 1
			macAddr, _ := net.ParseMAC(fmt.Sprintf("02:02:02:%02x:%02x:%02x", j, j, j))
			ipAddr := net.ParseIP(fmt.Sprintf("10.10.%d.%d", j, j))
			var ipv6Addr net.IP
			if j%2 == 0 {
				ipv6Addr = net.ParseIP(fmt.Sprintf("2016::%d:%d", j, j))
			}
			endpoint := EndpointInfo{
				PortNo:   uint32(NUM_AGENT + 2),
				MacAddr:  macAddr,
				Vlan:     1,
				IpAddr:   ipAddr,
				Ipv6Addr: ipv6Addr,
			}

			log.Infof("Installing local vxlan endpoint: %+v", endpoint)

			// Install the local endpoint
			err := vxlanAgents[i].AddLocalEndpoint(endpoint)
			if err != nil {
				t.Errorf("Error installing endpoint: %+v. Err: %v", endpoint, err)
			}
		}

		log.Infof("Finished adding local vxlan endpoint")

		// verify all ovs switches have this route
		for i := 0; i < NUM_AGENT; i++ {
			brName := "vxlanBridge" + fmt.Sprintf("%d", i)

			flowList, err := ofctlFlowDump(brName)
			if err != nil {
				t.Errorf("Error getting flow entries. Err: %v", err)
			}
			// verify flow entry exists
			for j := 0; j < NUM_AGENT; j++ {
				k := j + 1
				macFlowMatch := fmt.Sprintf("priority=100,dl_vlan=1,dl_dst=02:02:02:%02x:%02x:%02x", k, k, k)

				macTableId := MAC_DEST_TBL_ID
				if !ofctlFlowMatch(flowList, macTableId, macFlowMatch) {
					t.Errorf("Could not find the mac flow %s on ovs %s", macFlowMatch, brName)
				}

				log.Infof("Found macFlow %s on ovs %s", macFlowMatch, brName)
			}
		}

		log.Infof("Add vxlan endpoint successful.\n Testing Delete")

		for i := 0; i < NUM_AGENT; i++ {
			j := i + 1
			macAddr, _ := net.ParseMAC(fmt.Sprintf("02:02:02:%02x:%02x:%02x", j, j, j))
			ipAddr := net.ParseIP(fmt.Sprintf("10.10.%d.%d", j, j))
			var ipv6Addr net.IP
			if j%2 == 0 {
				ipv6Addr = net.ParseIP(fmt.Sprintf("2016::%d:%d", j, j))
			}
			endpoint := EndpointInfo{
				PortNo:   uint32(NUM_AGENT + 2),
				MacAddr:  macAddr,
				Vlan:     1,
				IpAddr:   ipAddr,
				Ipv6Addr: ipv6Addr,
			}

			log.Infof("Deleting local vxlan endpoint: %+v", endpoint)

			// Install the local endpoint
			err := vxlanAgents[i].RemoveLocalEndpoint(uint32(NUM_AGENT + 2))
			if err != nil {
				t.Errorf("Error deleting endpoint: %+v. Err: %v", endpoint, err)
			}
		}

		log.Infof("Deleted endpoints. Verifying they are gone")

		// verify flow is deleted
		for i := 0; i < NUM_AGENT; i++ {
			brName := "vxlanBridge" + fmt.Sprintf("%d", i)

			flowList, err := ofctlFlowDump(brName)
			if err != nil {
				t.Errorf("Error getting flow entries. Err: %v", err)
			}

			// verify flow entry exists
			for j := 0; j < NUM_AGENT; j++ {
				k := j + 1
				macFlowMatch := fmt.Sprintf("priority=100,dl_vlan=1,dl_dst=02:02:02:%02x:%02x:%02x", k, k, k)

				macTableId := MAC_DEST_TBL_ID
				if ofctlFlowMatch(flowList, macTableId, macFlowMatch) {
					t.Errorf("Still found the mac flow %s on ovs %s", macFlowMatch, brName)
				}
			}
		}
	}
}

// Run an ovs-ofctl command
func runOfctlCmd(cmd, brName string) ([]byte, error) {
	cmdStr := fmt.Sprintf("sudo /usr/bin/ovs-ofctl -O Openflow13 %s %s", cmd, brName)
	out, err := exec.Command("/bin/sh", "-c", cmdStr).Output()
	if err != nil {
		log.Errorf("error running ovs-ofctl %s %s. Error: %v", cmd, brName, err)
		return nil, err
	}

	return out, nil
}

// dump the flows and parse the Output
func ofctlFlowDump(brName string) ([]string, error) {
	flowDump, err := runOfctlCmd("dump-flows", brName)
	if err != nil {
		log.Errorf("Error running dump-flows on %s. Err: %v", brName, err)
		return nil, err
	}

	log.Debugf("Flow dump: %s", flowDump)
	flowOutStr := string(flowDump)
	flowDb := strings.Split(flowOutStr, "\n")[1:]

	log.Debugf("flowDb: %+v", flowDb)

	var flowList []string
	for _, flow := range flowDb {
		felem := strings.Fields(flow)
		if len(felem) > 2 {
			felem = append(felem[:1], felem[2:]...)
			felem = append(felem[:2], felem[4:]...)
			fstr := strings.Join(felem, " ")
			flowList = append(flowList, fstr)
		}
	}

	log.Debugf("flowList: %+v", flowList)

	return flowList, nil
}

// Find a flow in flow list and match its action
func ofctlFlowMatch(flowList []string, tableId int, matchStr string) bool {
	mtStr := fmt.Sprintf("table=%d, %s", tableId, matchStr)
	for _, flowEntry := range flowList {
		log.Debugf("Looking for %s in %s", mtStr, flowEntry)
		if strings.Contains(flowEntry, mtStr) {
			return true
		}
	}

	return false
}

func TestOfnetBgpPeerAddDelete(t *testing.T) {

	neighborAs := "500"
	peer := "50.1.1.2"
	routerIP := "50.1.1.1/24"
	as := "65002"
	//Add Bgp neighbor and check if it is successful

	for i := 0; i < NUM_VLRTR_AGENT; i++ {
		err := vlrtrAgents[i].AddBgp(routerIP, as, neighborAs, peer)
		if err != nil {
			t.Errorf("Error adding Bgp Neighbor: %v", err)
			return
		}

		timeout := grpc.WithTimeout(time.Second)
		conn, err := grpc.Dial("127.0.0.1:8080", timeout, grpc.WithBlock(), grpc.WithInsecure())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		client := api.NewGobgpApiClient(conn)
		if client == nil {
			t.Errorf("GoBgpApiclient is invalid")
		}
		arg := &api.Arguments{Name: peer}

		//Check if neighbor is added to bgp server
		bgpPeer, err := client.GetNeighbor(context.Background(), arg)
		if err != nil {
			t.Errorf("GetNeighbor failed: %v", err)
			return
		}

		//Delete BGP neighbor
		err = vlrtrAgents[i].DeleteBgp()
		if err != nil {
			t.Errorf("Error Deleting Bgp Neighbor: %v", err)
			return
		}

		//Check if neighbor is added to bgp server
		bgpPeer, err = client.GetNeighbor(context.Background(), arg)
		if bgpPeer != nil {
			t.Errorf("Neighbor is not deleted: %v", err)
			return
		}
	}
}

// Test adding/deleting Vlrouter routes
func TestOfnetVlrouteAddDelete(t *testing.T) {
	neighborAs := "500"
	peer := "50.1.1.2"
	routerIP := "50.1.1.1/24"
	as := "65002"
	//Add Bgp neighbor and check if it is successful

	for i := 0; i < NUM_VLRTR_AGENT; i++ {
		err := vlrtrAgents[i].AddBgp(routerIP, as, neighborAs, peer)
		if err != nil {
			t.Errorf("Error adding Bgp Neighbor: %v", err)
			return
		}

		macAddr, _ := net.ParseMAC("02:02:01:06:06:06")
		ipAddr := net.ParseIP("20.20.20.20")
		ipv6Addr := net.ParseIP("2020::20:20")
		endpoint := EndpointInfo{
			PortNo:   uint32(NUM_AGENT + 3),
			MacAddr:  macAddr,
			Vlan:     1,
			IpAddr:   ipAddr,
			Ipv6Addr: ipv6Addr,
		}

		log.Infof("Installing local vlrouter endpoint: %+v", endpoint)
		err = vlrtrAgents[i].AddNetwork(uint16(1), uint32(1), "20.20.20.254", "default")
		if err != nil {
			t.Errorf("Error adding vlan 1 . Err: %v", err)
		}

		// Install the local endpoint
		err = vlrtrAgents[i].AddLocalEndpoint(endpoint)
		if err != nil {
			t.Fatalf("Error installing endpoint: %+v. Err: %v", endpoint, err)
			return
		}

		log.Infof("Finished adding local vlrouter endpoint")

		// verify all ovs switches have this route
		brName := "vlrtrBridge" + fmt.Sprintf("%d", i)
		flowList, err := ofctlFlowDump(brName)
		if err != nil {
			t.Errorf("Error getting flow entries. Err: %v", err)
			return
		}

		// verify flow entry exists
		ipFlowMatch := fmt.Sprintf("priority=100,ip,nw_dst=20.20.20.20")
		ipTableId := IP_TBL_ID
		if !ofctlFlowMatch(flowList, ipTableId, ipFlowMatch) {
			t.Errorf("Could not find the route %s on ovs %s", ipFlowMatch, brName)
			return
		}

		log.Infof("Found ipflow %s on ovs %s", ipFlowMatch, brName)

		// verify IPv6 flow entry exists
		ipv6FlowMatch := fmt.Sprintf("priority=100,ipv6,ipv6_dst=2020::20:20")
		if !ofctlFlowMatch(flowList, ipTableId, ipv6FlowMatch) {
			t.Errorf("Could not find the route %s on ovs %s", ipv6FlowMatch, brName)
			return
		}
		log.Infof("Found ipv6 flow %s on ovs %s", ipv6FlowMatch, brName)

		log.Infof("Adding Vlrouter endpoint successful.\n Testing Delete")

		macAddr, _ = net.ParseMAC("02:02:01:06:06:06")
		ipAddr = net.ParseIP("20.20.20.20")
		ipv6Addr = net.ParseIP("2020::20:20")
		endpoint = EndpointInfo{
			PortNo:   uint32(NUM_AGENT + 3),
			MacAddr:  macAddr,
			Vlan:     1,
			IpAddr:   ipAddr,
			Ipv6Addr: ipv6Addr,
		}

		log.Infof("Deleting local vlrouter endpoint: %+v", endpoint)

		// Install the local endpoint
		err = vlrtrAgents[i].RemoveLocalEndpoint(uint32(NUM_AGENT + 3))
		if err != nil {
			t.Fatalf("Error deleting endpoint: %+v. Err: %v", endpoint, err)
			return
		}

		log.Infof("Deleted endpoints. Verifying they are gone")

		// verify flows are deleted
		brName = "vlrtrBridge" + fmt.Sprintf("%d", i)

		flowList, err = ofctlFlowDump(brName)
		if err != nil {
			t.Errorf("Error getting flow entries. Err: %v", err)
		}
		// verify flow entry exists
		ipFlowMatch = fmt.Sprintf("priority=100,ip,nw_dst=20.20.20.20")
		ipTableId = IP_TBL_ID
		if ofctlFlowMatch(flowList, ipTableId, ipFlowMatch) {
			t.Errorf("Still found the flow %s on ovs %s", ipFlowMatch, brName)
		}
		// verify IPv6 flow entry exists
		ipv6FlowMatch = fmt.Sprintf("priority=100,ipv6,ipv6_dst=2020::20:20")
		ipTableId = IP_TBL_ID
		if ofctlFlowMatch(flowList, ipTableId, ipv6FlowMatch) {
			t.Errorf("Still found the flow %s on ovs %s", ipv6FlowMatch, brName)
			return
		}
		err = vlrtrAgents[i].DeleteBgp()
		log.Infof("Verified all flows are deleted")
	}
}

// Test adding/deleting Vlrouter routes
func TestOfnetBgpVlrouteAddDelete(t *testing.T) {

	neighborAs := "500"
	peer := "50.1.1.3"
	routerIP := "50.1.1.2/24"
	as := "65002"
	//Add Bgp neighbor and check if it is successful

	for i := 0; i < NUM_VLRTR_AGENT; i++ {
		err := vlrtrAgents[i].AddBgp(routerIP, as, neighborAs, peer)
		time.Sleep(5 * time.Second)
		if err != nil {
			t.Errorf("Error adding Bgp Neighbor: %v", err)
			return
		}
		path := &api.Path{
			Pattrs: make([][]byte, 0),
		}
		nlri := bgp.NewIPAddrPrefix(32, "20.20.20.20")
		path.Nlri, _ = nlri.Serialize()
		origin, _ := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_EGP).Serialize()
		path.Pattrs = append(path.Pattrs, origin)
		aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65002})}
		aspath, _ := bgp.NewPathAttributeAsPath(aspathParam).Serialize()
		path.Pattrs = append(path.Pattrs, aspath)
		n, _ := bgp.NewPathAttributeNextHop("50.1.1.3").Serialize()
		path.Pattrs = append(path.Pattrs, n)
		vlrtrAgents[i].protopath.ModifyProtoRib(path)
		log.Infof("Adding path to the Bgp Rib")
		time.Sleep(2 * time.Second)

		// verify flow entry exists
		brName := "vlrtrBridge" + fmt.Sprintf("%d", i)

		flowList, err := ofctlFlowDump(brName)
		if err != nil {
			t.Errorf("Error getting flow entries. Err: %v", err)
		}
		ipFlowMatch := fmt.Sprintf("priority=100,ip,nw_dst=20.20.20.20")
		ipTableId := IP_TBL_ID
		if !ofctlFlowMatch(flowList, ipTableId, ipFlowMatch) {
			t.Errorf("Could not find the route %s on ovs %s", ipFlowMatch, brName)
			return
		}
		log.Infof("Found ipflow %s on ovs %s", ipFlowMatch, brName)

		// withdraw the route
		path.IsWithdraw = true
		vlrtrAgents[i].protopath.ModifyProtoRib(path)
		log.Infof("Withdrawing route from BGP rib")

		// verify flow entry exists
		brName = "vlrtrBridge" + fmt.Sprintf("%d", i)

		flowList, err = ofctlFlowDump(brName)
		if err != nil {
			t.Errorf("Error getting flow entries. Err: %v", err)
		}

		ipFlowMatch = fmt.Sprintf("priority=100,ip,nw_dst=20.20.20.20")
		ipTableId = IP_TBL_ID
		if ofctlFlowMatch(flowList, ipTableId, ipFlowMatch) {
			t.Errorf("Found the route %s on ovs %s which was withdrawn", ipFlowMatch, brName)
			return
		}
		log.Infof("ipflow %s on ovs %s has been deleted from OVS", ipFlowMatch, brName)
	}
}

// Verify if the flow entries are installed on vlan bridge
func TestVlanFlowEntry(t *testing.T) {
	for i := 0; i < NUM_AGENT; i++ {
		brName := "vlanBridge" + fmt.Sprintf("%d", i)

		flowList, err := ofctlFlowDump(brName)
		if err != nil {
			t.Errorf("Error getting flow entries. Err: %v", err)
		}

		// Check if ARP Request redirect entry is installed
		arpFlowMatch := fmt.Sprintf("priority=100,arp,arp_op=1 actions=CONTROLLER")
		if !ofctlFlowMatch(flowList, 0, arpFlowMatch) {
			t.Errorf("Could not find the route %s on ovs %s", arpFlowMatch, brName)
			return
		}
		log.Infof("Found arp redirect flow %s on ovs %s", arpFlowMatch, brName)
	}
}

// Verify if the flow entries are installed on vlan bridge
func TestVxlanFlowEntry(t *testing.T) {
	for i := 0; i < NUM_AGENT; i++ {
		brName := "vxlanBridge" + fmt.Sprintf("%d", i)

		flowList, err := ofctlFlowDump(brName)
		if err != nil {
			t.Errorf("Error getting flow entries. Err: %v", err)
		}

		// Check if ARP Request redirect entry is installed
		arpFlowMatch := fmt.Sprintf("priority=100,arp,arp_op=1 actions=CONTROLLER")
		if !ofctlFlowMatch(flowList, 0, arpFlowMatch) {
			t.Errorf("Could not find the route %s on ovs %s", arpFlowMatch, brName)
			return
		}
		log.Infof("Found arp redirect flow %s on ovs %s", arpFlowMatch, brName)
	}
}

// Test Vrouter Network Delete with Remote Endpoints
func TestOfnetVrtrDeleteNwWithRemoteEP(t *testing.T) {
	testVlan := 100
	for iter := 0; iter < NUM_ITER; iter++ {

		// Add Vrtr Network
		for i := 0; i < NUM_AGENT; i++ {
			err := vrtrAgents[i].AddNetwork(uint16(testVlan), uint32(testVlan), "", "default")
			if err != nil {
				t.Errorf("Error adding vlan %d. Err: %v", testVlan, err)
				return
			}
		}

		log.Infof("Finished adding network")

		// Add Vrtr Endpoints
		for i := 0; i < NUM_AGENT; i++ {
			j := i + 1

			macAddr, _ := net.ParseMAC(fmt.Sprintf("02:02:02:%02x:%02x:%02x", j, j, j))
			ipAddr := net.ParseIP(fmt.Sprintf("10.10.%d.%d", j, j))
			endpoint := EndpointInfo{
				PortNo:  uint32(NUM_AGENT + 2),
				MacAddr: macAddr,
				Vlan:    uint16(testVlan),
				IpAddr:  ipAddr,
			}

			log.Infof("Installing local vrouter endpoint: %+v", endpoint)

			// Install the local endpoint
			err := vrtrAgents[i].AddLocalEndpoint(endpoint)
			if err != nil {
				t.Fatalf("Error installing endpoint: %+v. Err: %v", endpoint, err)
				return
			}
		}

		log.Infof("Finished adding endpoints")

		for i := 0; i < NUM_AGENT; i++ {
			j := i + 1
			macAddr, _ := net.ParseMAC(fmt.Sprintf("02:02:02:%02x:%02x:%02x", j, j, j))
			ipAddr := net.ParseIP(fmt.Sprintf("10.10.%d.%d", j, j))
			endpoint := EndpointInfo{
				PortNo:  uint32(NUM_AGENT + 2),
				MacAddr: macAddr,
				Vlan:    uint16(testVlan),
				IpAddr:  ipAddr,
			}

			log.Infof("Deleting local vrouter endpoint: %+v", endpoint)

			// Install the local endpoint
			err := vrtrAgents[i].RemoveLocalEndpoint(uint32(NUM_AGENT + 2))
			if err != nil {
				t.Fatalf("Error deleting endpoint: %+v. Err: %v", endpoint, err)
				return
			}

			// Remove network before endpoint cleanup on other agents
			err = vrtrAgents[i].RemoveNetwork(uint16(testVlan), uint32(testVlan), "", "default")
			if err != nil {
				t.Errorf("Error removing vlan %d. Err: %v", testVlan, err)
				return
			}

		}

		log.Infof("All networks are deleted")
	}
}

// Test Vxlan Network Delete with Remote Endpoints
func TestOfnetVxlanDeleteNwWithRemoteEP(t *testing.T) {
	testVlan := 100
	for iter := 0; iter < NUM_ITER; iter++ {
		// Add vxlan network
		for i := 0; i < NUM_AGENT; i++ {

			// Add Vxlan Network and Endpoints
			err := vxlanAgents[i].AddNetwork(uint16(testVlan), uint32(testVlan), "", "default")
			if err != nil {
				t.Errorf("Error adding vlan %d. Err: %v", testVlan, err)
				return
			}
		}

		// Add vxlan endpoints
		for i := 0; i < NUM_AGENT; i++ {
			j := i + 1

			macAddr, _ := net.ParseMAC(fmt.Sprintf("02:02:02:%02x:%02x:%02x", j, j, j))
			ipAddr := net.ParseIP(fmt.Sprintf("10.10.%d.%d", j, j))
			endpoint := EndpointInfo{
				PortNo:  uint32(NUM_AGENT + 2),
				MacAddr: macAddr,
				Vlan:    uint16(testVlan),
				IpAddr:  ipAddr,
			}

			log.Infof("Installing local vxlan endpoint: %+v", endpoint)

			// Install the local endpoint
			err := vxlanAgents[i].AddLocalEndpoint(endpoint)
			if err != nil {
				t.Fatalf("Error installing endpoint: %+v. Err: %v", endpoint, err)
				return
			}
		}

		log.Infof("Finished adding network and endpoints")

		for i := 0; i < NUM_AGENT; i++ {
			j := i + 1
			macAddr, _ := net.ParseMAC(fmt.Sprintf("02:02:02:%02x:%02x:%02x", j, j, j))
			ipAddr := net.ParseIP(fmt.Sprintf("10.10.%d.%d", j, j))
			endpoint := EndpointInfo{
				PortNo:  uint32(NUM_AGENT + 2),
				MacAddr: macAddr,
				Vlan:    uint16(testVlan),
				IpAddr:  ipAddr,
			}

			log.Infof("Deleting local vxlan endpoint: %+v", endpoint)

			// Install the local endpoint
			err := vxlanAgents[i].RemoveLocalEndpoint(uint32(NUM_AGENT + 2))
			if err != nil {
				t.Fatalf("Error deleting endpoint: %+v. Err: %v", endpoint, err)
				return
			}

			// Remove network before endpoint cleanup on other agents
			err = vxlanAgents[i].RemoveNetwork(uint16(testVlan), uint32(testVlan), "", "default")
			if err != nil {
				t.Errorf("Error removing vlan %d. Err: %v", testVlan, err)
				return
			}

		}

		log.Infof("All networks are deleted")
	}
}

// Wait for debug and cleanup
func TestWaitAndCleanup(t *testing.T) {
	time.Sleep(1 * time.Second)

	// Disconnect from switches.
	for i := 0; i < NUM_AGENT; i++ {
		vrtrAgents[i].Delete()
		vxlanAgents[i].Delete()
		vlanAgents[i].Delete()
	}
	for i := 0; i < NUM_VLRTR_AGENT; i++ {
		vlrtrAgents[i].Delete()
	}

	for i := 0; i < NUM_AGENT; i++ {
		brName := "vrtrBridge" + fmt.Sprintf("%d", i)
		log.Infof("Deleting OVS bridge: %s", brName)
		err := ovsDrivers[i].DeleteBridge(brName)
		if err != nil {
			t.Errorf("Error deleting the bridge. Err: %v", err)
		}
	}
	for i := 0; i < NUM_AGENT; i++ {
		brName := "vxlanBridge" + fmt.Sprintf("%d", i)
		log.Infof("Deleting OVS bridge: %s", brName)
		err := ovsDrivers[NUM_AGENT+i].DeleteBridge(brName)
		if err != nil {
			t.Errorf("Error deleting the bridge. Err: %v", err)
		}
	}
	for i := 0; i < NUM_AGENT; i++ {
		brName := "vlanBridge" + fmt.Sprintf("%d", i)
		log.Infof("Deleting OVS bridge: %s", brName)
		err := ovsDrivers[(2*NUM_AGENT)+i].DeleteBridge(brName)
		if err != nil {
			t.Errorf("Error deleting the bridge. Err: %v", err)
		}
	}
	for i := 0; i < NUM_VLRTR_AGENT; i++ {
		brName := "vlrtrBridge" + fmt.Sprintf("%d", i)
		log.Infof("Deleting OVS bridge: %s", brName)
		err := ovsDrivers[(3*NUM_AGENT)+i].DeleteBridge(brName)
		if err != nil {
			t.Errorf("Error deleting the bridge. Err: %v", err)
		}
	}
}
