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
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/gorilla/rpc"
	gJson "github.com/gorilla/rpc/json"
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
	config   *tCommon.TrustDomainConfig
	log      *log.Logger
	session  *client.Session
	name     string // name of the kaetzchen service
	provider string // name of the provider hosting the service
}

// Write implements libtalek/common.ReplicaInterface
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

// BatchRead implements libtalek/common.ReplicaInterface
func (r *ReplicaKPC) BatchRead(args *tCommon.BatchReadRequest, reply *tCommon.BatchReadReply) error {
	serialized, err := cbor.Marshal(args)
	if err != nil {
		return err
	}

	// wrap the serialized command in ReplicaCommand
	serialized, err = cbor.Marshal(&common.ReplicaRequest{Command: common.ReplicaWriteCommand, Payload: serialized})
	if err != nil {
		return err
	}
	rawResp, err := r.session.BlockingSendUnreliableMessage(r.name, r.provider, serialized)
	if err != nil {
		return err
	}
	return cbor.Unmarshal(rawResp, reply)
}

func NewReplicaKPC(name string, provider string, session *client.Session, config *tCommon.TrustDomainConfig) *ReplicaKPC {
	return &ReplicaKPC{
		name:     name,
		provider: provider,
		log:      log.New(os.Stdout, "frontend", log.Flags()),
		session:  session,
	}
}

// NewKPFrontendServer creates a new Frontend implementing HTTP.Handler and using Replicas reached via Katzenpost
func NewKPFrontendServer(name string, session *client.Session, serverConfig *server.Config, replicas []*ReplicaKPC) *kpTalekFrontend {
	fe := &kpTalekFrontend{}

	rpcs := make([]tCommon.ReplicaInterface, len(replicas))
	for i, r := range replicas {
		rk := NewReplicaKPC(r.name, r.provider, session, r.config)
		rpcs[i] = rk
	}

	// Create a Frontend
	fe.Frontend = server.NewFrontend(name, serverConfig, rpcs)

	// Set up the RPC server component.
	fe.Server = rpc.NewServer()
	fe.Server.RegisterCodec(&gJson.Codec{}, "application/json")
	fe.Server.RegisterTCPService(fe.Frontend, "Frontend")
	http.Handle("/rpc", fe.Server)
	return fe
}

func main() {
	var kpConfigPath string
	var listen string
	var verbose bool

	// add mixnet config
	flag.StringVar(&kpConfigPath, "kpconfig", "client.toml", "Katzenpost Configuration")
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

	replicas := make([]*ReplicaKPC, 0)
	trustDomainCfgs := make([]*tCommon.TrustDomainConfig, 0)
	commonCfgs := make([]*tCommon.Config, 0)
	for _, desc := range descs {
		// get the publickeys from the MixDescriptor
		md, err := pkiDoc.GetProvider(desc.Provider)
		if err != nil {
			fmt.Println(err)
			continue
		}

		// obtain the plugin parameters
		kpReplicaParams, ok := md.Kaetzchen[talekReplicaService]
		if !ok {
			fmt.Println("Failed to find talek replica plugin parameters for ", desc.Provider)
			continue
		}

		// obtain a trustdomain from parameters
		trustDomainCfg, err := trustDomainFromParams(desc.Name, desc.Provider, kpReplicaParams)
		if err != nil {
			fmt.Println("trustDomainFromParams returned %v", err)
			continue
		}

		// keep the trustDomain configs for the client config
		trustDomainCfgs = append(trustDomainCfgs, trustDomainCfg)

		// obtain a common config from parameters
		commonCfg, err := commonConfigFromParams(kpReplicaParams)
		if err != nil {
			fmt.Println("commonConfigFromParams returned %v", err)
			continue
		}
		commonCfgs = append(commonCfgs, commonCfg)

		// make a replica instance
		replicas = append(replicas, NewReplicaKPC(desc.Name, desc.Provider, session, trustDomainCfg))
	}
	// XXX // check that all replicas agree on parameters

	// create a server.Config
	serverConfig := &server.Config{
		// XXX: this should be learned from PKI too
		Config:           commonCfgs[0],
		TrustDomain:      &tCommon.TrustDomainConfig{},
		TrustDomainIndex: 0,
	}

	// start the frontend server
	f := NewKPFrontendServer("Talek Frontend", session, serverConfig, replicas)
	f.Frontend.Verbose = true // *verbose
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	// generate a client configuration to use with talekclient
	clientConfig := libtalek.ClientConfig{Config: commonCfgs[0]}
	clientConfig.Config = commonCfgs[0]

	<-sigCh
}
func trustDomainFromParams(endpoint string, provider string, kpReplicaParams map[string]interface{}) (*tCommon.TrustDomainConfig, error) {
	rawPubKey, ok := kpReplicaParams["PublicKey"]
	if !ok {
		return nil, fmt.Errorf("Failed to find talek replica parameter PublickKey for ", provider)
	}
	rawSignPubKey, ok := kpReplicaParams["SignPublicKey"]
	if !ok {
		return nil, fmt.Errorf("Failed to find talek replica parameter SignPublickKey for ", provider)
	}

	// copy the key material into arrays
	var signPubKeyArray [32]byte
	var pubKeyArray [32]byte
	if signPubKeyb64, ok := rawSignPubKey.(string); ok {
		signPubKey, err := base64.StdEncoding.DecodeString(signPubKeyb64)
		if err != nil {
			return nil, err
		}
		copy(signPubKeyArray[:], signPubKey)
	} else {
		return nil, fmt.Errorf("Invalid type for SignPublicKey")
	}
	if pubKeyb64, ok := rawPubKey.(string); ok {
		pubKey, err := base64.StdEncoding.DecodeString(pubKeyb64)
		if err != nil {
			return nil, err
		}
		copy(pubKeyArray[:], pubKey)
	} else {
		return nil, fmt.Errorf("Invalid type for PublicKey")
	}

	// make a TrustDomainConfig for this replica
	trustDomainCfg := tCommon.TrustDomainConfig{
		Name:          endpoint + "@" + provider,
		Address:       "kp://" + endpoint + "@" + provider,
		IsValid:       true,
		IsDistributed: true,
		PublicKey:     pubKeyArray,
		SignPublicKey: signPubKeyArray,
	}
	return &trustDomainCfg, nil
}

func commonConfigFromParams(kpReplicaParams map[string]interface{}) (*tCommon.Config, error) {
	cfg := tCommon.Config{}
	var err error

	rawConfig, ok := kpReplicaParams["Config"]
	if !ok {
		return nil, fmt.Errorf("No Parameter Config")
	}
	configStr, ok := rawConfig.(string)
	if !ok {
		return nil, fmt.Errorf("Wrong type for Config %T, must be string", rawConfig)
	}
	configBytes, err := base64.StdEncoding.DecodeString(configStr)
	if err != nil {
		return nil, fmt.Errorf("Wrong encoding for Config: must be base64")
	}
	err = json.Unmarshal(configBytes, cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
