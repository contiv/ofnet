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
// This file contains the ofnet master implementation

import (
    "net/rpc"

    "github.com/contiv/ofnet/rpcHub"

    log "github.com/Sirupsen/logrus"
)


// Ofnet master state
type OfnetMaster struct {
    rpcServer   *rpc.Server

    // Database of agent nodes
    agentDb     map[string]*OfnetNode

    // Route Database
    routeDb     map[string]*OfnetRoute
}

// Information about each node
type OfnetNode struct {
    HostAddr    string
}

// Create new Ofnet master
func NewOfnetMaster() *OfnetMaster {
    // Create the master
    master := new(OfnetMaster)

    // Init params
    master.agentDb = make(map[string]*OfnetNode)
    master.routeDb = make(map[string]*OfnetRoute)

    // Create a new RPC server
    master.rpcServer = rpcHub.NewRpcServer(9001)

    // Register RPC handler
    master.rpcServer.Register(master)

    return master
}

// Register an agent
func (self *OfnetMaster) RegisterNode(hostAddr *string, ret *bool) error {
    // Create a node
    node := new(OfnetNode)
    node.HostAddr = *hostAddr

    // Add it to DB
    self.agentDb[*hostAddr] = node

    log.Infof("Registered node: %+v", node)

    // FIXME: Send all existing routes

    return nil
}

// Add a route
func (self *OfnetMaster) RouteAdd (route *OfnetRoute, ret *bool) error {
    // Save the route in DB
    self.routeDb[route.IpAddr.String()] = route

    // Publish it to all agents except where it came from
    for _, node := range self.agentDb {
        if (node.HostAddr != route.OriginatorIp.String()) {
            var resp bool

            log.Infof("Sending Route: %+v to node %s", route, node.HostAddr)

            client := rpcHub.Client(node.HostAddr, OFNET_AGENT_PORT)
            err := client.Call("Vrouter.RouteAdd", route, &resp)
            if (err != nil) {
                log.Errorf("Error adding route to %s. Err: %v", node.HostAddr, err)
            }
        }
    }

    *ret = true
    return nil
}

// Delete a route
func (self *OfnetMaster) RouteDel (route *OfnetRoute, ret *bool) error {
    return nil
}
