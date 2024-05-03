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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"gopkg.in/op/go-logging.v1"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"github.com/katzenpost/katzenpost/talek/replica/common"
	tCommon "github.com/privacylab/talek/common"
	"github.com/privacylab/talek/server"
)

const capability = "talek_replica"

type talekRequestHandler struct {
	worker.Worker
	backing string
	replica *server.Replica
	config  *server.Config
	log     *logging.Logger
	write   func(cborplugin.Command)
}

func main() {
	var logLevel string
	var logDir string
	var backing string
	var cfgFile string
	var commonCfgFile string
	var listen string
	var index int

	flag.StringVar(&backing, "backing", "cpu.0", "PIR daemon method")
	flag.StringVar(&cfgFile, "config", "replica.conf", "Talek Replica Configuration")
	flag.StringVar(&commonCfgFile, "common", "common.conf", "Talek Common Configuration")
	flag.IntVar(&index, "index", 0, "Talek Replica Trustdomain Index") // wtfbbq
	flag.StringVar(&listen, "listen", ":8080", "Listening Address")
	flag.StringVar(&logDir, "log_dir", "", "logging directory")
	flag.StringVar(&logLevel, "log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	flag.Parse()

	// Ensure that the log directory exists.
	s, err := os.Stat(logDir)
	if os.IsNotExist(err) {
		fmt.Printf("Log directory '%s' doesn't exist.", logDir)
		os.Exit(1)
	}
	if !s.IsDir() {
		fmt.Println("Log directory must actually be a directory.")
		os.Exit(1)
	}

	// Log to a file.
	logFile := path.Join(logDir, fmt.Sprintf("talek_replica.%d.log", os.Getpid()))
	logBackend, err := log.New(logFile, logLevel, false)
	if err != nil {
		panic(err)
	}
	serverLog := logBackend.GetLogger("talek_replica")

	// start service
	tmpDir, err := os.MkdirTemp("", "talek_replica")
	if err != nil {
		panic(err)
	}
	socketFile := filepath.Join(tmpDir, fmt.Sprintf("%d.talek_replica.socket", os.Getpid()))

	// instantiate replica configuration, with defaults
	serverConfig := &server.Config{
		Config:           &tCommon.Config{},
		TrustDomain:      &tCommon.TrustDomainConfig{},
		TrustDomainIndex: index,
	}

	// read cfgFile
	cfgString, err := ioutil.ReadFile(cfgFile)
	if err != nil {
		panic(err)
	}

	// deserialize cfgFile
	if err = json.Unmarshal(cfgString, &serverConfig); err != nil {
		panic(err)
	}

	// read commonCfgFile
	commonString, err := ioutil.ReadFile(commonCfgFile)
	if err != nil {
		panic(err)
	}

	// deserialize common configuration elements
	if err = json.Unmarshal(commonString, serverConfig); err != nil {
		panic(err)
	}

	// emit socketFile to stdout, because this tells the mix server where to connect
	// do this BEFORE starting the replica, because talek writes to stdout too
	// XXX: unfortunately mix server tries to dial the socket before we've started it
	// there is a workaround in PR 485
	fmt.Printf("%s\n", socketFile)

	// instantiate replica srever
	replica := server.NewReplica(serverConfig.TrustDomain.Name, backing, *serverConfig)
	h := &talekRequestHandler{replica: replica, log: serverLog, config: serverConfig, backing: backing}
	cbserver := cborplugin.NewServer(serverLog, socketFile, h)
	cbserver.Accept()
	cbserver.Wait()
	replica.Close()
	os.Remove(socketFile)
}

func (s *talekRequestHandler) OnCommand(cmd cborplugin.Command) error {
	// deserialize request
	switch cmd := cmd.(type) {
	case *cborplugin.Request:
		// expected type
		r := new(common.ReplicaRequest)
		_, err := cbor.UnmarshalFirst(cmd.Payload, r)
		if err != nil {
			s.log.Errorf("Did not deserialize a ReplicaRequest")
			return nil
		}
		switch r.Command {
		case common.ReplicaRequestCommand:
			// deserialize BatchReadRequest
			request := new(tCommon.BatchReadRequest)

			_, err = cbor.UnmarshalFirst(r.Payload, request)
			if err != nil {
				s.log.Errorf("replica.Request failure to unmarshal args: %v", err)
				return nil
			}

			// run the command asynchronously
			s.Go(func() {
				reply := new(tCommon.BatchReadReply)
				// run the comand asynchronously
				req, _ := json.MarshalIndent(request, "", "  ")
				s.log.Debugf("starting BatchRead:\n%s\n", req)

				err = s.replica.BatchRead(request, reply)
				if err != nil {
					s.log.Errorf("BatchRead failure: %v", err)
					reply.Err = err.Error()
				} else {
					pp, _ := json.MarshalIndent(reply, "", "  ")
					s.log.Debugf("BatchRead got reply:\n%s\n", pp)
				}

				serialized, err := cbor.Marshal(reply)
				if err != nil {
					s.log.Errorf("cbor.Marshal failure: %v", err)
				}
				if len(serialized) > cmd.ResponseSize {
					s.log.Fatalf("response too large for payoad")
				}
				s.write(&cborplugin.Response{SURB: cmd.SURB, Payload: serialized})
			})
		case common.ReplicaWriteCommand:
			// deserialize ReplicaWriteArgs
			args := new(tCommon.ReplicaWriteArgs)
			_, err = cbor.UnmarshalFirst(r.Payload, args)
			if err != nil {
				s.log.Errorf("replica.Write failure to unmarshal args: %v", err)
				return nil
			}

			// run the comand asynchronously
			s.Go(func() {
				reply := new(tCommon.ReplicaWriteReply)
				req, _ := json.MarshalIndent(args, "", "  ")
				s.log.Debugf("starting Write:\n%s\n", req)
				err = s.replica.Write(args, reply)
				if err != nil {
					s.log.Errorf("replica.Write failure: %v", err)
				} else {
					pp, _ := json.MarshalIndent(reply, "", "  ")
					s.log.Debugf("replica.Write got reply:\n%s\n", pp)
				}
				serialized, err := cbor.Marshal(reply)
				if err != nil {
					s.log.Errorf("cbor.Marshal failure: %v", err)
				}
				if len(serialized) > cmd.ResponseSize {
					s.log.Fatalf("response too large for payoad")
				}
				s.write(&cborplugin.Response{SURB: cmd.SURB, Payload: serialized})
			})
		default:
			s.log.Errorf("Got Invalid type %T", r.Command)
			return errors.New("Invalid ReplicaCommand type")
		}
	case *cborplugin.ParametersRequest:
		params := paramsFromServerConfig(s.config)
		s.write(params)
	case *cborplugin.Document:
		// restart the replica service if our TrustDomainIndex has changed
		doc := &cmd.Document
		s.log.Notice("Received PKI Document for Epoch %d", doc.Epoch)

		// find all of the talek replica instances
		replicas := make([]*pki.MixDescriptor, 0)
		for _, provider := range doc.Providers {
			for capa, _ := range provider.Kaetzchen {
				if capa == capability {
					s.log.Notice("Found %s@%s in PKI", capability, provider.Name)
					replicas = append(replicas, provider)
					break
				}
			}
		}

		// check which TrustDomainIndex this replica is by PKI order
		inPKI := false
		for idx, replica := range replicas {
			params := replica.Kaetzchen[capability]
			// XXX ideally we would verify ownership of this key
			p := params["PublicKey"]
			publicKey := p.(string)
			publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
			if err != nil {
				s.log.Errorf("Failed to decode PublicKey from %s", replica.Name)
				return nil
			}
			if bytes.Equal(publicKeyBytes, s.config.TrustDomain.PublicKey[:]) {
				inPKI = true
				s.log.Notice("Found this Replica in position %d", idx)
				if idx != s.config.TrustDomainIndex {
					s.log.Notice("Restarting replica Idx %d as TrustDomainIndex %d", s.config.TrustDomainIndex, idx)
					s.replica.Close()
					s.config.TrustDomainIndex = idx
					s.replica = server.NewReplica(s.config.TrustDomain.Name, s.backing, *s.config)
				}
			}
		}

		if !inPKI {
			// service is not in the PKI
			s.log.Errorf("TrustDomain %s not found in PKI", s.config.TrustDomain.Name)
			return nil
		}
	default:
		return errors.New("Invalid Command, expected cborplugin.Request")
	}

	return nil
}

func (s *talekRequestHandler) RegisterConsumer(svr *cborplugin.Server) {
	s.write = svr.Write
}

func paramsFromServerConfig(config *server.Config) *cborplugin.Parameters {
	params := make(cborplugin.Parameters)
	params["PublicKey"] = base64.StdEncoding.EncodeToString(config.TrustDomain.PublicKey[:])
	params["SignPublicKey"] = base64.StdEncoding.EncodeToString(config.TrustDomain.SignPublicKey[:])

	cfgJson, err := json.Marshal(config)
	if err != nil {
		panic("server config is not marshalable")
	}

	params["Config"] = base64.StdEncoding.EncodeToString(cfgJson)
	return &params
}
