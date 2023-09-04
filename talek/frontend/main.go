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
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/gorilla/rpc"
	"github.com/gorilla/rpc/json"
	"github.com/katzenpost/katzenpost/client"
	//"github.com/katzenpost/katzenpost/server/cborplugin"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/talek/replica/common"
	tCommon "github.com/privacylab/talek/common"
	"github.com/privacylab/talek/libtalek"
	"github.com/privacylab/talek/server"
)

const talekReplicaService = "talek_replica"

type kpTalekFrontend struct {
	Frontend *server.Frontend
	log      *log.Logger
	name     string
	*rpc.Server
}

// ReplicaKPC is a stub for the replica RPC interface
// it wraps Write and BatchRead commands to Replicas using Katzenpost
type ReplicaKPC struct {
	log      *tCommon.Logger
	session  *client.Session
	name     string // name of the kaetzchen service
	provider string // name of the provider hosting the service
}

func (r *ReplicaKPC) Write(args *tCommon.ReplicaWriteArgs, reply *tCommon.ReplicaWriteReply) error {
	serialized, err := cbor.Marshal(args)
	if err != nil {
		return err
	}
	// wrap the serialized command in ReplicaCommand
	serialized, err = cbor.Marshal(&common.ReplicaRequest{Command: common.ReplicaRequestCommand, Payload: serialized})
	rawResp, err := r.session.BlockingSendUnreliableMessage(r.name, r.provider, serialized)
	if err != nil {
		return err
	}
	return cbor.Unmarshal(rawResp, reply)

}

func (r *ReplicaKPC) BatchRead(args *tCommon.BatchReadRequest, reply *tCommon.BatchReadReply) error {
	serialized, err := cbor.Marshal(args)
	if err != nil {
		return err
	}

	// wrap the serialized command in ReplicaCommand
	serialized, err = cbor.Marshal(&common.ReplicaRequest{Command: common.ReplicaWriteCommand, Payload: serialized})
	rawResp, err := r.session.BlockingSendUnreliableMessage(r.name, r.provider, serialized)
	if err != nil {
		return err
	}
	return cbor.Unmarshal(rawResp, reply)
}

func NewReplicaKPC(name string, session *client.Session, config *tCommon.TrustDomainConfig) *ReplicaKPC {
	return &ReplicaKPC{
		name:    name,
		log:     tCommon.NewLogger(name),
		session: session,
	}
}

// NewKPFrontendServer creates a new Frontend implementing HTTP.Handler and using Replicas reached via Katzenpost
func NewKPFrontendServer(name string, session *client.Session, serverConfig *server.Config, replicas []*tCommon.TrustDomainConfig) *kpTalekFrontend {
	fe := &kpTalekFrontend{}

	rpcs := make([]tCommon.ReplicaInterface, len(replicas))
	for i, r := range replicas {
		rk := NewReplicaKPC(r.Name, session, r)
		rpcs[i] = rk
	}

	// Create a Frontend
	fe.Frontend = server.NewFrontend(name, serverConfig, rpcs)

	// Set up the RPC server component.
	fe.Server = rpc.NewServer()
	fe.Server.RegisterCodec(&json.Codec{}, "application/json")
	fe.Server.RegisterTCPService(fe.Frontend, "Frontend")

	return fe
}

func main() {
	var configPath string
	var kpConfigPath string
	var commonPath string
	var listen string
	var verbose bool

	// add mixnet config
	flag.StringVar(&kpConfigPath, "kpconfig", "client.toml", "Katzenpost Configuration")
	//flag.StringVar(&backing, "backing", "cpu.0", "PIR daemon method")
	flag.StringVar(&configPath, "config", "replica.conf", "Talek Replica Configuration")
	flag.StringVar(&commonPath, "common", "common.conf", "Talek Common Configuration")
	flag.StringVar(&listen, "listen", ":8080", "Listening Address")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output")
	flag.Parse()

	// load katzenpost client configuration
	var cfg *config.Config
	var err error
	cfg, err = config.LoadFile(kpConfigPath)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	// create a client
	c, err := client.New(cfg)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	// create a server.Config
	serverConfig := &server.Config{
		Config:           &tCommon.Config{},
		WriteInterval:    time.Second,
		ReadInterval:     time.Second,
		ReadBatch:        8,
		TrustDomain:      &tCommon.TrustDomainConfig{},
		TrustDomainIndex: 0,
	}

	config := libtalek.ClientConfigFromFile(configPath)
	if config == nil {
		flag.Usage()
		return
	}

	// bootstrap mixnet
	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second*30)
	session, err := c.NewTOFUSession(ctx)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	cancelFn()

	// get a pki doc
	pkiDoc := session.CurrentDocument()
	if pkiDoc == nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	// find replicas from pki
	descs, err := session.GetServices(talekReplicaService)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	replicas := make([]tCommon.ReplicaInterface, len(descs), 0)
	for i, d := range descs {
		// get the publickeys from the MixDescriptor
		md, err := pkiDoc.GetProvider(d.Provider)
		if err != nil {
			fmt.Println(err)
			continue
		}

		// obtain the plugin parameters
		kpReplicaParams, ok := md.Kaetzchen[talekReplicaService]
		if !ok {
			fmt.Println("Failed to find talek replica plugin parameters for ", d.Provider)
			continue
		}

		pubKey, ok := kpReplicaParams["PublicKey"]
		if !ok {
			fmt.Println("Failed to find talek replica parameter PublickKey for ", d.Provider)
			continue
		}
		signPubKey, ok := kpReplicaParams["SignPublicKey"]
		if !ok {
			fmt.Println("Failed to find talek replica parameter SignPublickKey for ", d.Provider)
			continue
		}

		// copy the key material into arrays
		var signPubKeyArray [32]byte
		var pubKeyArray [32]byte
		if signPubKey, ok := signPubKey.([]byte); ok {
			copy(signPubKeyArray[:], signPubKey)
		} else {
			fmt.Println("Invalid type for SignPublicKey")
			continue
		}
		if pubKey, ok := pubKey.([]byte); ok {
			copy(pubKeyArray[:], pubKey)
		} else {
			fmt.Println("Invalid type for PublicKey")
			continue
		}

		// make a TrustDomainConfig for this replica
		trustDomainCfg := tCommon.TrustDomainConfig{
			Name:          d.Name + "@" + d.Provider,
			Address:       "kp://" + d.Name + "@" + d.Provider,
			IsValid:       true,
			IsDistributed: true,
			PublicKey:     pubKeyArray,
			SignPublicKey: signPubKeyArray,
		}

		replicaName := d.Name + "@" + d.Provider
		replicas[i] = NewReplicaKPC(replicaName, session, &trustDomainCfg)
	}

	// XXX: can TrustDomainConfig have an Address of format kaetchen@provider
	f := server.NewFrontendServer("Talek Frontend", serverConfig, config.TrustDomains)

	// instantiate Frontend
	f.Frontend = server.NewFrontend(serverConfig.TrustDomain.Name, serverConfig, replicas)

	// make a new frontend server for kp
	f.Frontend.Verbose = true // *verbose
	listener, err := f.Run(listen)
	if err != nil {
		log.Printf("Couldn't listen to frontend address: %v\n", err)
		return
	}

	log.Println("Running.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	<-sigCh
	listener.Close()
}
