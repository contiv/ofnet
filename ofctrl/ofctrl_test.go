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
package ofctrl

import (
    "log"
    "testing"

    "github.com/shaleman/libOpenflow/openflow13"
)

type OfActor struct {
    Switch *OFSwitch
}

func (o *OfActor) PacketRcvd(sw *OFSwitch, packet *PacketIn) {
    log.Printf("App: Received packet: %+v", packet)
}

func (o *OfActor) SwitchConnected(sw *OFSwitch) {
    log.Printf("App: Switch connected: %v", sw.DPID())

    // Store switch for later use
    o.Switch = sw
}

func (o *OfActor) SwitchDisconnected(sw *OFSwitch) {
    log.Printf("App: Switch connected: %v", sw.DPID())
}


var ofActor OfActor


func TestOfctrlInit(t *testing.T) {
    // Create a controller
    ctrler := NewController("ovsbr0", &ofActor)

    // start listening
    ctrler.Listen(":6633")
}

/* This was just an experiment
// Test connecting over unix socket
func TestUnixSocket(t *testing.T) {
    // Create a controller
    ctrler := NewController("ovsbr0", &ofActor)

    // Connect to unix socket
    conn, err := net.Dial("unix", "/var/run/openvswitch/ovsbr0.mgmt")
    if (err != nil) {
        log.Printf("Failed to connect to unix socket. Err: %v", err)
        t.Errorf("Failed to connect to unix socket. Err: %v", err)
        return
    }

    // Handle connection
    ctrler.handleConnection(conn)

    time.After(100 * time.Second)
}
*/
