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
package rpcHub
// Hub and spoke RPC implementation based on JSON RPC library

import (
    "fmt"
    "net"
    "net/rpc"
    "net/rpc/jsonrpc"

    log "github.com/Sirupsen/logrus"
)

// Create a new RPC server
func NewRpcServer(portNo uint16) *rpc.Server{
    server := rpc.NewServer()

    // Listen on RPC port in background
    go func() {
        // Listens on a port
        l, e := net.Listen("tcp", fmt.Sprintf(":%d", portNo))
        if e != nil {
            log.Fatal("listen error:", e)
        }

        for {
            conn, err := l.Accept()
            if err != nil {
                log.Fatal(err)
            }

            go server.ServeCodec(jsonrpc.NewServerCodec(conn))
        }
    }()

    return server
}

// DB of all existing clients
var clientDb map[string]*rpc.Client = make(map[string]*rpc.Client)

// Create a new client
func NewRpcClient(servAddr string, portNo uint16) *rpc.Client {
    // Connect to the server
    conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", servAddr, portNo))
    if err != nil {
        panic(err)
    }

    // Create an RPC client
    client := jsonrpc.NewClient(conn)

    // FIXME: handle disconnects

    return client
}

// Get a client to the rpc server
func Client(servAddr string, portNo uint16) *rpc.Client {
    // Return the client if it already exists
    if (clientDb[servAddr] != nil) {
        return clientDb[servAddr]
    }

    // Create a new client and add it to the DB
    client := NewRpcClient(servAddr, portNo)
    clientDb[servAddr] = client

    return client
}
