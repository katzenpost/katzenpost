// bench_test.go - benchmark tests
// Copyright (C) 2023  Masala
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
//
// Package bench tests performance of minclient and client send/receive methods
//go:build docker_test
// +build docker_test

package bench

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	cConstants "github.com/katzenpost/katzenpost/client/constants"
	"github.com/katzenpost/katzenpost/client/utils"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/minclient"
)

var (
	clientTestCfg              = "testdata/client.toml"
	initialPKIConsensusTimeout = 45 * time.Second

	// prometheus counters
	clientMessageSent = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_client_message_sent",
			Help: "Number of outgoing messages sent by client",
		},
	)
	clientMessageReceived = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_client_message_receive",
			Help: "Number of incoming messages seen by client",
		},
	)
	minclientMessageSent = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_minclient_message_sent",
			Help: "Number of outgoing messages sent by minclient",
		},
	)
	minclientMessageReceived = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_minclient_message_receive",
			Help: "Number of incoming messages seen by minclient",
		},
	)
	minclientEmptyMessageReceived = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_minclient_empty_message_receive",
			Help: "Number of empty messages seen by minclient",
		},
	)

	minclientAckReceived = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_minclient_ack_receive",
			Help: "Number of incoming surb-ack seen by minclient",
		},
	)
)

var testSignatureScheme = signSchemes.ByName("Ed25519")

func getClientCfg(f string) *config.Config {
	cfg, err := config.LoadFile(f)
	if err != nil {
		panic(err)
	}
	return cfg
}

func getClient(cfg *config.Config) *client.Client {
	client, err := client.New(cfg)
	if err != nil {
		panic(err)
	}
	return client
}

func DockerTestBenchClient(t *testing.T) {
	require := require.New(t)
	c := getClient(getClientCfg(clientTestCfg))
	ctx := context.Background()
	_, err := c.NewTOFUSession(ctx)
	require.NoError(err)
}

type MinclientBench struct {
	worker.Worker
	sync.Mutex
	cfg             *config.Config
	log             *logging.Logger
	linkKey         kem.PrivateKey
	minclientConfig *minclient.ClientConfig
	minclient       *minclient.Client
	provider        *pki.MixDescriptor
	onDoc           chan struct{}
	onConn          chan struct{}

	msgs  map[[cConstants.MessageIDLength]byte]struct{}
	surbs map[[sConstants.SURBIDLength]byte]struct{}
}

func (b *MinclientBench) setup() {
	// this is a config for client.Client, but we'll use it for the PKI configuration bootstrapping
	b.msgs = make(map[[cConstants.MessageIDLength]byte]struct{})
	b.surbs = make(map[[sConstants.SURBIDLength]byte]struct{})
	b.onDoc = make(chan struct{}, 0)
	b.onConn = make(chan struct{}, 0)

	cfg := getClientCfg(clientTestCfg)
	b.cfg = cfg
	logBackend, err := log.New(cfg.Logging.File, cfg.Logging.Level, cfg.Logging.Disable)
	if err != nil {
		panic(err)
	}

	b.log = logBackend.GetLogger("MinclientBench")

	myScheme := schemes.ByName(cfg.WireKEMScheme)
	if myScheme == nil {
		panic("WireKEMScheme is invalid")
	}

	_, b.linkKey, err = schemes.ByName(cfg.WireKEMScheme).GenerateKeyPair()
	blob, err := b.linkKey.Public().MarshalBinary()
	if err != nil {
		panic(err)
	}
	idHash := blake2b.Sum256(blob)
	proxyContext := fmt.Sprintf("session %d", rand.NewMath().Uint64())
	pkiClient, err := cfg.NewPKIClient(logBackend, cfg.UpstreamProxyConfig(), b.linkKey, cfg.SphinxGeometry)
	currentEpoch, _, _ := epochtime.Now()
	ctx, cancel := context.WithTimeout(context.Background(), initialPKIConsensusTimeout)
	defer cancel()
	doc, _, err := pkiClient.Get(ctx, currentEpoch)
	if err != nil {
		panic(err)
	}
	desc, err := client.SelectGatewayNode(doc)
	if err != nil {
		panic(err)
	}
	b.provider = desc
	idkey, err := testSignatureScheme.UnmarshalBinaryPublicKey(b.provider.IdentityKey)
	if err != nil {
		panic(err)
	}
	b.minclientConfig = &minclient.ClientConfig{
		LinkKemScheme:       myScheme,
		SphinxGeometry:      cfg.SphinxGeometry,
		User:                string(idHash[:]),
		Gateway:             b.provider.Name,
		GatewayKeyPin:       idkey,
		LinkKey:             b.linkKey,
		LogBackend:          logBackend,
		PKIClient:           pkiClient,
		OnConnFn:            b.onConnection,
		OnMessageFn:         b.onMessage,
		OnACKFn:             b.onAck,
		OnDocumentFn:        b.onDocument,
		DialContextFn:       cfg.UpstreamProxyConfig().ToDialContext(proxyContext),
		PreferedTransports:  cfg.Debug.PreferedTransports,
		MessagePollInterval: time.Duration(cfg.Debug.PollingInterval) * time.Millisecond,
		EnableTimeSync:      false, // Be explicit about it.
	}

	b.minclient, err = minclient.New(b.minclientConfig)
	if err != nil {
		panic(err)
	}
}

func (b *MinclientBench) Start(t *testing.T) {
	b.setup()
	<-b.onConn
	// TODO: start benchmark timers
	b.Go(b.sendWorker)
}

func (b *MinclientBench) GetService(serviceName string) (*utils.ServiceDescriptor, error) {
	doc := b.minclient.CurrentDocument()
	if doc == nil {
		return nil, errors.New("pki doc is nil")
	}
	descs := utils.FindServices(serviceName, doc)
	if len(descs) == 0 {
		return nil, errors.New("error, GetService failure, service not found in pki doc")
	}
	serviceDescriptors := make([]*utils.ServiceDescriptor, len(descs))
	for i, s := range descs {
		s := s
		serviceDescriptors[i] = &s
	}
	return serviceDescriptors[rand.NewMath().Intn(len(serviceDescriptors))], nil
}

func (b *MinclientBench) sendWorker() {
	// get loop service descriptor
	desc, err := b.GetService(cConstants.LoopService)
	if err != nil {
		panic(err)
	}

	for {
		select {
		case <-b.HaltCh():
			return
		default:
		}
		surbID := new([sConstants.SURBIDLength]byte)
		_, err := io.ReadFull(rand.Reader, surbID[:])
		if err != nil {
			panic(err)
		}
		crap := make([]byte, b.cfg.SphinxGeometry.UserForwardPayloadLength)
		_, _, err = b.minclient.SendCiphertext(desc.Name, desc.Provider, surbID, crap)
		if err != nil {
			panic(err)
		}
		minclientMessageSent.Inc()

		// add to waiting ack map
		b.Lock()
		b.surbs[*surbID] = struct{}{}
		b.Unlock()
	}
}

func (b *MinclientBench) Stop() {
	// TODO: stop benchmark timers
	b.Halt()
	b.minclient.Shutdown()
	b.minclient.Wait()
}

func (b *MinclientBench) onEmpty() error {
	minclientEmptyMessageReceived.Inc()
	b.log.Debugf("OnEmpty")
	return nil
}

func (b *MinclientBench) onConnection(err error) {
	// TODO: keep track of stats / time / etc
	b.log.Debugf("OnConnection")
	if err != nil {
		return
	}
	select {
	case b.onConn <- struct{}{}:
	default:
	}
}

func (b *MinclientBench) onMessage(mesg []byte) error {
	minclientMessageReceived.Inc()
	b.log.Debugf("OnMessage")
	return nil
}

func (b *MinclientBench) onAck(surbid *[sConstants.SURBIDLength]byte, mesg []byte) error {
	// just increment total counter for now, but we will want
	// to track other types of statistics such as duplicate or unexpected Acks receive
	minclientAckReceived.Inc()
	b.log.Debugf("OnAck")
	b.Lock()
	defer b.Unlock()
	_, ok := b.surbs[*surbid]
	if !ok {
		return errors.New("Lost a SURBID!")
	}
	// remove ack'd messages from map
	delete(b.surbs, *surbid)
	return nil
}

func (b *MinclientBench) onDocument(doc *pki.Document) {
	// TODO: keep track of stats / time / etc
	b.log.Debugf("OnDocument")
	select {
	case b.onDoc <- struct{}{}:
	default:
	}
}

type ClientBench struct {
	worker.Worker
	sync.Mutex
	cfg        *config.Config
	log        *logging.Logger
	c          *client.Client
	s          *client.Session
	onSent     chan struct{}
	msgs       map[[cConstants.MessageIDLength]byte]struct{}
	numWorkers int
}

func (b *ClientBench) Start(t *testing.T) {
	require := require.New(t)
	// start event sink readers
	b.numWorkers = 3
	b.onSent = make(chan struct{})
	b.msgs = make(map[[cConstants.MessageIDLength]byte]struct{})
	cfg := getClientCfg(clientTestCfg)
	b.cfg = cfg
	var err error
	b.c, err = client.New(cfg)
	require.NoError(err)

	b.log = b.c.GetBackendLog().GetLogger("ClientBench")

	ctx := context.Background()
	b.s, err = b.c.NewTOFUSession(ctx)
	require.NoError(err)

	for i := 0; i < b.numWorkers; i++ {
		b.Go(b.eventWorker)
	}

	b.s.WaitForDocument(ctx)
	b.Go(b.sendWorker)
}

func (b *ClientBench) sendWorker() {
	// get loop service descriptor
	desc, err := b.s.GetService(cConstants.LoopService)
	if err != nil {
		panic(err)
	}
	crap := make([]byte, b.cfg.SphinxGeometry.UserForwardPayloadLength)

	for {
		// keep sending till we fill the egressQueue, then block onSent
		_, err := b.s.SendUnreliableMessage(desc.Name, desc.Provider, crap)
		if err != nil {
			select {
			case <-b.HaltCh():
				return
			case <-b.onSent:
			}
		}
	}
}

func (b *ClientBench) onEvent(event interface{}) {
	// handle client event types
	// with a prometheus counter on each type
	switch e := event.(type) {
	case *client.ConnectionStatusEvent:
	case *client.MessageReplyEvent:
		clientMessageReceived.Inc()
		b.Lock()
		delete(b.msgs, *e.MessageID)
		b.Unlock()
	case *client.MessageSentEvent:
		select {
		case b.onSent <- struct{}{}:
		default:
		}
		clientMessageSent.Inc()
		// keep track of MessageID, SURBID
		b.Lock()
		b.msgs[*e.MessageID] = struct{}{}
		b.Unlock()
	case *client.NewDocumentEvent:
		return
	default:
		panic(e)
	}
}

func (b *ClientBench) Stop() {
	b.Halt()
	b.s.Shutdown()
	b.s.Wait()
}

func (b *ClientBench) eventWorker() {
	for {
		select {
		case <-b.HaltCh():
			return
		case evt := <-b.s.EventSink:
			b.onEvent(evt)
		}
	}
}

func TestDockerBenchMinclient(t *testing.T) {
	//require := require.New(t)
	m := MinclientBench{}
	m.Start(t)
	t.Logf("Starting minclient benchmark")
	<-time.After(1 * time.Minute)
	m.Stop()
	t.Logf("Stopping minclient benchmark")
	m.Wait()
}

func TestDockerBenchClient(t *testing.T) {
	//require := require.New(t)
	m := ClientBench{}
	m.Start(t)
	t.Logf("Starting client benchmark")
	<-time.After(1 * time.Minute)
	m.Stop()
	t.Logf("Stopping client benchmark")
	m.Wait()
}

func init() {
	// Register metrics
	prometheus.MustRegister(clientMessageSent)
	prometheus.MustRegister(clientMessageReceived)
	prometheus.MustRegister(minclientMessageSent)
	prometheus.MustRegister(minclientMessageReceived)
	prometheus.MustRegister(minclientAckReceived)
	prometheus.MustRegister(minclientEmptyMessageReceived)

	// Expose registered metrics via HTTP
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe("127.0.0.1:6543", nil)
}
