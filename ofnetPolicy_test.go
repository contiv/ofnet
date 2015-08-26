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

import (
	"net"
	"testing"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/ofnet/ovsdbDriver"
)

func TestPolicy(t *testing.T) {
	rpcPort := uint16(9101)
	ovsPort := uint16(9151)
	lclIp := net.ParseIP("10.10.10.10")
	ofnetAgent, err := NewOfnetAgent("vrouter", lclIp, rpcPort, ovsPort)
	if err != nil {
		t.Fatalf("Error creating ofnet agent. Err: %v", err)
	}

	// Override MyAddr to local host
	ofnetAgent.MyAddr = "127.0.0.1"

	log.Infof("Created vrouter ofnet agent: %v", ofnetAgent)

	brName := "ovsbr11"
	ovsDriver := ovsdbDriver.NewOvsDriver(brName)
	err = ovsDriver.AddController("127.0.0.1", ovsPort)
	if err != nil {
		t.Fatalf("Error adding controller to ovs: %s", brName)
	}

	// Wait for 10sec for switch to connect to controller
	time.Sleep(10 * time.Second)

	// create policy agent
	policyAgent := NewPolicyAgent(ofnetAgent, ofnetAgent.ofSwitch)

	// Init tables
	policyAgent.InitTables(IP_TBL_ID)

	// Add an Endpoint
	err = policyAgent.AddEndpoint(&OfnetEndpoint{
		EndpointID:    "1234",
		EndpointGroup: 100,
		IpAddr:        net.ParseIP("10.10.10.10"),
	})
	if err != nil {
		t.Errorf("Error adding endpoint. Err: %v", err)
	}

	var resp bool
	rule := &OfnetPolicyRule{
		RuleId:           "1234",
		SrcEndpointGroup: 100,
		DstEndpointGroup: 200,
		SrcIpAddr:        "10.10.10.10/24",
		DstIpAddr:        "10.1.1.1/24",
	}

	// Add a policy
	err = policyAgent.AddRule(rule, &resp)
	if err != nil {
		t.Errorf("Error installing rule {%+v}. Err: %v", rule, err)
	}
}
