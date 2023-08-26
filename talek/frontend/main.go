// Copyright (C) 2023  Masala.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"github.com/katzenpost/katzenpost/talek/replica/common"
	tCommon "github.com/privacylab/talek/common"
	"github.com/privacylab/talek/server"
	"github.com/privacylab/talek/libtalek"
)

type kpTalekFrontend struct {
	frontend *server.Frontend
}

// ReplicaKPC is a stub for the replica RPC interface
// it wraps Write and BatchRead commands to Replicas using Katzenpost
type ReplicaKPC struct {
	log          *log.Logger
	session      *client.Session
	name         string // name of the kaetzchen service
	provider     string // name of the provider hosting the service
}

func (r *ReplicaKPC) Write(args *tCommon.ReplicaWriteArgs, reply *tCommon.ReplicaWriteReply) error {
	// TODO: send a replica Write command
	return errors.New("NotImplemented")
}

func (r *ReplicaKPC) BatchRead(args *tCommon.BatchReadRequest, reply *tCommon.BatchReadReply) error {
	// TODO: send a replica BatchRead command
	return errors.New("NotImplemented")
}

func NewReplicaKPC(name, provider string, config *tCommon.TrustDomainConfig, client *client.Client) *ReplicaKPC {
	session, err := client.NewTOFUSession(context.Background())
	return &ReplicaKPC{
		name: name,
		provider: provider,
		log: client.GetLogger(fmt.Sprintf("%s:%s", name, provider)),
		session: 
	}
}

// NewKPFrontendServer creates a new Frontend implementing HTTP.Handler and using Replicas reached via Katzenpost
func NewKPFrontendServer(name string, serverConfig *tCommon.Config, replicas []*common.TrustDomainConfig) *FrontendServer {
	fe := &FrontendServer{}
	fe.log = log.New(os.Stdout, "[FrontendServer:"+name+"] ", log.Ldate|log.Ltime|log.Lshortfile)
	fe.name = name

	rpcs := make([]common.ReplicaInterface, len(replicas))
	for i, r := range replicas {
		rpcs[i] = common.NewReplicaKP(r.Name, r)
	}

	fe.Frontend = NewFrontend(name, serverConfig, rpcs)

	// Set up the RPC server component.
	fe.Server = rpc.NewServer()
	fe.Server.RegisterCodec(&json.Codec{}, "application/json")
	fe.Server.RegisterTCPService(fe.Frontend, "Frontend")

	return fe
}


func main() {
	var configPath string
	var commonPath string
	var listen string
	var verbose bool 

	// add mixnet config
	//flag.StringVar(&backing, "backing", "cpu.0", "PIR daemon method")
	flag.StringVar(&configPath, "config", "replica.conf", "Talek Replica Configuration")
	flag.StringVar(&commonPath, "common", "common.conf", "Talek Common Configuration")
	flag.StringVar(&listen, "listen", ":8080", "Listening Address")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output")
	flag.Parse()

	// createa  server Config
	serverConfig := server.Config{
		Config:           &tCommon.Config{},
		WriteInterval:    time.Second,
		ReadInterval:     time.Second,
		ReadBatch:        8,
		TrustDomain:      &tCommon.TrustDomainConfig{},
		TrustDomainIndex: 0,
	}

	config := libtalek.ClientConfigFromFile(*configPath)
	if config == nil {
		flag.Usage()
		return
	}
	serverConfig := server.ConfigFromFile(commonPath, config.Config)

	f := server.NewFrontendServer("Talek Frontend", serverConfig, config.TrustDomains)


	// TODO: bootstrap mixnet, find replicas from pki
	replicas := make([]*server.Replica, 0)

	// instantiate Frontend
	frontend := server.NewFrontend(serverConfig.TrustDomain.Name, serverConfig, replicas)

	// make a new frontend server for kp

	f.Frontend.Verbose = true // *verbose
	listener, err := f.Run(listen)
	if err != nil {
		log.Printf("Couldn't listen to frontend address: %v\n", err)
		return
	}

	log.Println("Running.")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	listener.Close()
}
