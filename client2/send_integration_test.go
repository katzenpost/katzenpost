// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client2

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/pigeonhole"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// createFullMockPKIDocument creates a PKI document with gateway, service nodes,
// mix layers, and replica descriptors — sufficient for Sphinx path construction.
func createFullMockPKIDocument(t *testing.T, geo *geo.Geometry) (*cpki.Document, *[32]byte, *[32]byte, []byte) {
	nikeScheme := nikeSchemes.ByName(geo.NIKEName)
	require.NotNil(t, nikeScheme)

	currentEpoch, _, _ := epochtime.Now()
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()

	// Generate gateway node
	gatewayPub, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	gatewayIdKey, err := gatewayPub.MarshalBinary()
	require.NoError(t, err)
	gatewayLinkPub, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	gatewayLinkKey, err := gatewayLinkPub.MarshalBinary()
	require.NoError(t, err)
	gatewayIdHash := hash.Sum256(gatewayIdKey)

	// Gateway also needs a MixKey for path construction
	gatewayMixPub, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	gatewayMixKey, err := gatewayMixPub.MarshalBinary()
	require.NoError(t, err)

	gatewayDesc := &cpki.MixDescriptor{
		Name:          "gateway1",
		IdentityKey:   gatewayIdKey,
		LinkKey:       gatewayLinkKey,
		IsGatewayNode: true,
		Addresses:     map[string][]string{"tcp4": {"tcp4://127.0.0.1:30001"}},
		MixKeys:       map[uint64][]byte{currentEpoch: gatewayMixKey, currentEpoch + 1: gatewayMixKey},
	}

	// Generate service node with courier
	servicePub, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	serviceIdKey, err := servicePub.MarshalBinary()
	require.NoError(t, err)
	serviceLinkPub, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	serviceLinkKey, err := serviceLinkPub.MarshalBinary()
	require.NoError(t, err)
	serviceIdHash := hash.Sum256(serviceIdKey)
	serviceQueueID := []byte("courier")

	// Service node also needs a MixKey
	serviceMixPub, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	serviceMixKey, err := serviceMixPub.MarshalBinary()
	require.NoError(t, err)

	serviceDesc := &cpki.MixDescriptor{
		Name:          "servicenode1",
		IdentityKey:   serviceIdKey,
		LinkKey:       serviceLinkKey,
		IsServiceNode: true,
		Addresses:     map[string][]string{"tcp4": {"tcp4://127.0.0.1:30002"}},
		Kaetzchen: map[string]map[string]interface{}{
			"courier": {"endpoint": "courier"},
			"echo":    {"endpoint": "+echo"},
		},
		MixKeys:       map[uint64][]byte{currentEpoch: serviceMixKey, currentEpoch + 1: serviceMixKey},
	}

	// Generate 3 mix layers — each needs MixKeys for the current epoch
	topology := make([][]*cpki.MixDescriptor, 3)
	for layer := 0; layer < 3; layer++ {
		mixPub, _, err := nikeScheme.GenerateKeyPair()
		require.NoError(t, err)
		mixIdKey, err := mixPub.MarshalBinary()
		require.NoError(t, err)
		mixLinkPub, _, err := nikeScheme.GenerateKeyPair()
		require.NoError(t, err)
		mixLinkKey, err := mixLinkPub.MarshalBinary()
		require.NoError(t, err)

		// Generate a mix key for the current epoch
		mixKeyPub, _, err := nikeScheme.GenerateKeyPair()
		require.NoError(t, err)
		mixKeyBytes, err := mixKeyPub.MarshalBinary()
		require.NoError(t, err)

		mixDesc := &cpki.MixDescriptor{
			Name:        fmt.Sprintf("mix%d", layer+1),
			IdentityKey: mixIdKey,
			LinkKey:     mixLinkKey,
			Addresses:   map[string][]string{"tcp4": {fmt.Sprintf("tcp4://127.0.0.1:3000%d", layer+3)}},
			MixKeys:     map[uint64][]byte{currentEpoch: mixKeyBytes, currentEpoch + 1: mixKeyBytes},
		}
		topology[layer] = []*cpki.MixDescriptor{mixDesc}
	}

	// Use pre-generated CTIDH keypair fixtures for replica descriptors
	loadCTIDHFixtures()
	replicaDescs := make([]*cpki.ReplicaDescriptor, 2)
	configuredReplicaKeys := make([][]byte, 2)
	for i := 0; i < 2; i++ {
		rPubBytes := ctidhFixtures[i].PubBytes
		rIdKey := make([]byte, 32)
		_, err := rand.Reader.Read(rIdKey)
		require.NoError(t, err)

		replicaDescs[i] = &cpki.ReplicaDescriptor{
			Name:        fmt.Sprintf("replica%d", i),
			IdentityKey: rIdKey,
			EnvelopeKeys: map[uint64][]byte{
				replicaEpoch: rPubBytes,
			},
		}
		configuredReplicaKeys[i] = rIdKey
	}

	doc := &cpki.Document{
		Epoch:                         currentEpoch,
		Topology:                      topology,
		GatewayNodes:                  []*cpki.MixDescriptor{gatewayDesc},
		ServiceNodes:                  []*cpki.MixDescriptor{serviceDesc},
		StorageReplicas:               replicaDescs,
		ConfiguredReplicaIdentityKeys: configuredReplicaKeys,
		LambdaP:                       0.001,
		LambdaPMaxDelay:               1000,
		Mu:                            0.005,
		MuMaxDelay:                    1000,
	}

	return doc, &gatewayIdHash, &serviceIdHash, serviceQueueID
}

// setupFullClient creates a Client with Sphinx, PKI, and a mock connection
// that can compose and "send" packets (sends are drained by a goroutine).
func setupFullClient(t *testing.T) (*Daemon, *Client, *[AppIDLength]byte, chan *Response, chan []byte) {
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	port, err := getFreePort()
	require.NoError(t, err)
	cfg.ListenAddress = fmt.Sprintf("127.0.0.1:%d", port)
	cfg.PigeonholeGeometry = &pigeonholeGeo.Geometry{
		MaxPlaintextPayloadLength: 1000,
		NIKEName:                  replicaCommon.NikeScheme.Name(),
	}

	sphinxInstance, err := sphinx.FromGeometry(cfg.SphinxGeometry)
	require.NoError(t, err)

	doc, gatewayHash, _, _ := createFullMockPKIDocument(t, cfg.SphinxGeometry)
	currentEpoch, _, _ := epochtime.Now()

	client := &Client{
		cfg:       cfg,
		sphinx:    sphinxInstance,
		geo:       cfg.SphinxGeometry,
		logbackend: logBackend,
		log:       logBackend.GetLogger("client"),
		pki: &pki{
			log: logBackend.GetLogger("pki"),
		},
	}
	client.pki.c = client
	client.pki.docs.Store(currentEpoch, &CachedDoc{Doc: doc})

	// Set up connection with gateway and a draining sendCh
	conn := newConnection(client)
	conn.gatewayLock.Lock()
	conn.gateway = gatewayHash
	conn.gatewayLock.Unlock()
	conn.queueID = []byte("testqueue")
	conn.isConnectedLock.Lock()
	conn.isConnected = true
	conn.isConnectedLock.Unlock()
	client.conn = conn

	// Drain packets from sendCh
	packetCh := make(chan []byte, 100)
	go func() {
		for {
			select {
			case ctx := <-conn.sendCh:
				packetCh <- ctx.pkt
				ctx.doneFn(nil)
			case <-conn.HaltCh():
				return
			}
		}
	}()

	rates := &Rates{}
	egressCh := make(chan *Request, 10)
	listener, err := NewListener(client, rates, egressCh, logBackend, nil)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Shutdown() })

	d := &Daemon{
		cfg:                       cfg,
		logbackend:                logBackend,
		log:                       logBackend.GetLogger("test"),
		client:                    client,
		listener:                  listener,
		arqSurbIDMap:              make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqEnvelopeHashMap:        make(map[[32]byte]*[sphinxConstants.SURBIDLength]byte),
		replies:                   make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		decoys:                    make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		replyLock:          new(sync.Mutex),
		copyStreamEncoders:        make(map[[thin.StreamIDLength]byte]*pigeonhole.CopyStreamEncoder),
		secureRand:                rand.NewMath(),
		timerQueue:                NewTimerQueue(func(interface{}) {}),
		gcSurbIDCh:                make(chan *[sphinxConstants.SURBIDLength]byte, 10),
		arqTimerQueue:             NewTimerQueue(func(interface{}) {}),
	}
	d.timerQueue.Start()
	d.arqTimerQueue.Start()
	t.Cleanup(func() {
		d.timerQueue.Halt()
		d.timerQueue.Wait()
		d.arqTimerQueue.Halt()
		d.arqTimerQueue.Wait()
	})

	testAppID := &[AppIDLength]byte{}
	copy(testAppID[:], []byte("full-client-apid"))

	responseCh := make(chan *Response, 10)
	mockConn := &mockIncomingConn{
		appID:      testAppID,
		responseCh: responseCh,
	}
	listener.connsLock.Lock()
	listener.conns[*testAppID] = mockConn.toIncomingConn(listener, logBackend)
	listener.connsLock.Unlock()

	return d, client, testAppID, responseCh, packetCh
}

func TestComposeSphinxPacketForQuery(t *testing.T) {
	_, client, _, _, _ := setupFullClient(t)

	serviceDesc := client.cfg.SphinxGeometry
	_ = serviceDesc

	// Get a service node from the PKI doc
	_, doc := client.CurrentDocument()
	require.NotNil(t, doc)
	require.NotEmpty(t, doc.ServiceNodes)
	serviceIdHash := hash.Sum256(doc.ServiceNodes[0].IdentityKey)

	surbID := &[sphinxConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbID[:])
	require.NoError(t, err)

	pkt, surbKey, rtt, err := client.ComposeSphinxPacketForQuery(&thin.SendChannelQuery{
		DestinationIdHash: &serviceIdHash,
		RecipientQueueID:  []byte("courier"),
		Payload:           []byte("test payload"),
	}, surbID)
	require.NoError(t, err)
	require.NotEmpty(t, pkt)
	require.NotEmpty(t, surbKey)
	require.True(t, rtt > 0)
}

func TestSendPacketViaMockConnection(t *testing.T) {
	_, client, _, _, packetCh := setupFullClient(t)

	err := client.SendPacket([]byte("fake-sphinx-packet"))
	require.NoError(t, err)

	select {
	case pkt := <-packetCh:
		require.Equal(t, []byte("fake-sphinx-packet"), pkt)
	case <-time.After(5 * time.Second):
		t.Fatal("packet not received")
	}
}

func TestStartResendingEncryptedMessage_FullPipeline(t *testing.T) {
	d, client, testAppID, responseCh, packetCh := setupFullClient(t)

	// First encrypt a write operation to get valid ciphertext
	_, doc := client.CurrentDocument()
	require.NotNil(t, doc)

	// Create a keypair
	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("start-resend-q00"))

	// Use the daemon to create a keypair first
	kpQueryID := &[thin.QueryIDLength]byte{}
	copy(kpQueryID[:], []byte("keypair-query000"))
	d.newKeypair(&Request{
		AppID: testAppID,
		NewKeypair: &thin.NewKeypair{
			QueryID: kpQueryID,
			Seed:    seed,
		},
	})

	var kpResp *Response
	select {
	case kpResp = <-responseCh:
		require.NotNil(t, kpResp.NewKeypairReply)
		require.Equal(t, thin.ThinClientSuccess, kpResp.NewKeypairReply.ErrorCode)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for keypair")
	}

	// Now encrypt a write
	ewQueryID := &[thin.QueryIDLength]byte{}
	copy(ewQueryID[:], []byte("encrypt-write000"))
	d.encryptWrite(&Request{
		AppID: testAppID,
		EncryptWrite: &thin.EncryptWrite{
			QueryID:         ewQueryID,
			Plaintext:       []byte("test message for full pipeline write"),
			WriteCap:        kpResp.NewKeypairReply.WriteCap,
			MessageBoxIndex: kpResp.NewKeypairReply.FirstMessageIndex,
		},
	})

	var ewResp *Response
	select {
	case ewResp = <-responseCh:
		require.NotNil(t, ewResp.EncryptWriteReply)
		require.Equal(t, thin.ThinClientSuccess, ewResp.EncryptWriteReply.ErrorCode)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for encrypt write")
	}

	// Now start resending — this exercises the full pipeline:
	// validation → courier selection → Sphinx packet composition → ARQ setup → send
	envHash := ewResp.EncryptWriteReply.EnvelopeHash
	d.startResendingEncryptedMessage(&Request{
		AppID: testAppID,
		StartResendingEncryptedMessage: &thin.StartResendingEncryptedMessage{
			QueryID:            queryID,
			WriteCap:           kpResp.NewKeypairReply.WriteCap,
			EnvelopeDescriptor: ewResp.EncryptWriteReply.EnvelopeDescriptor,
			MessageCiphertext:  ewResp.EncryptWriteReply.MessageCiphertext,
			EnvelopeHash:       envHash,
		},
	})

	// Verify a packet was sent
	select {
	case pkt := <-packetCh:
		require.NotEmpty(t, pkt, "Sphinx packet should have been sent")
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for packet send")
	}

	// Verify ARQ state was set up
	d.replyLock.Lock()
	found := false
	for _, msg := range d.arqSurbIDMap {
		if msg.EnvelopeHash != nil && *msg.EnvelopeHash == *envHash {
			found = true
			require.False(t, msg.IsRead)
			require.Equal(t, ARQStateWaitingForACK, msg.State)
			break
		}
	}
	d.replyLock.Unlock()
	require.True(t, found, "ARQ message should be in arqSurbIDMap")
}

func TestStartResendingCopyCommand_FullPipeline(t *testing.T) {
	d, _, testAppID, responseCh, packetCh := setupFullClient(t)

	// Create a keypair for the copy command's WriteCap
	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	kpQueryID := &[thin.QueryIDLength]byte{}
	copy(kpQueryID[:], []byte("copy-keypair-q00"))
	d.newKeypair(&Request{
		AppID: testAppID,
		NewKeypair: &thin.NewKeypair{
			QueryID: kpQueryID,
			Seed:    seed,
		},
	})

	var kpResp *Response
	select {
	case kpResp = <-responseCh:
		require.NotNil(t, kpResp.NewKeypairReply)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("copy-cmd-query00"))

	d.startResendingCopyCommand(&Request{
		AppID: testAppID,
		StartResendingCopyCommand: &thin.StartResendingCopyCommand{
			QueryID:  queryID,
			WriteCap: kpResp.NewKeypairReply.WriteCap,
		},
	})

	// Verify a packet was sent
	select {
	case pkt := <-packetCh:
		require.NotEmpty(t, pkt)
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for packet")
	}
}

func TestCancelResendingEncryptedMessage_FullPipeline(t *testing.T) {
	d, _, testAppID, responseCh, packetCh := setupFullClient(t)

	// First set up an ARQ via startResendingEncryptedMessage
	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	kpQueryID := &[thin.QueryIDLength]byte{}
	copy(kpQueryID[:], []byte("cancel-kp-query0"))
	d.newKeypair(&Request{
		AppID: testAppID,
		NewKeypair: &thin.NewKeypair{QueryID: kpQueryID, Seed: seed},
	})
	var kpResp *Response
	select {
	case kpResp = <-responseCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	ewQueryID := &[thin.QueryIDLength]byte{}
	copy(ewQueryID[:], []byte("cancel-ew-query0"))
	d.encryptWrite(&Request{
		AppID: testAppID,
		EncryptWrite: &thin.EncryptWrite{
			QueryID:         ewQueryID,
			Plaintext:       []byte("message to cancel"),
			WriteCap:        kpResp.NewKeypairReply.WriteCap,
			MessageBoxIndex: kpResp.NewKeypairReply.FirstMessageIndex,
		},
	})
	var ewResp *Response
	select {
	case ewResp = <-responseCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	startQueryID := &[thin.QueryIDLength]byte{}
	copy(startQueryID[:], []byte("cancel-start-q00"))
	envHash := ewResp.EncryptWriteReply.EnvelopeHash

	d.startResendingEncryptedMessage(&Request{
		AppID: testAppID,
		StartResendingEncryptedMessage: &thin.StartResendingEncryptedMessage{
			QueryID:            startQueryID,
			WriteCap:           kpResp.NewKeypairReply.WriteCap,
			EnvelopeDescriptor: ewResp.EncryptWriteReply.EnvelopeDescriptor,
			MessageCiphertext:  ewResp.EncryptWriteReply.MessageCiphertext,
			EnvelopeHash:       envHash,
		},
	})

	// Drain the packet
	select {
	case <-packetCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for packet")
	}

	// Now cancel it
	cancelQueryID := &[thin.QueryIDLength]byte{}
	copy(cancelQueryID[:], []byte("cancel-cancel-q0"))
	d.cancelResendingEncryptedMessage(&Request{
		AppID: testAppID,
		CancelResendingEncryptedMessage: &thin.CancelResendingEncryptedMessage{
			QueryID:      cancelQueryID,
			EnvelopeHash: envHash,
		},
	})

	// Should get two responses: cancellation of the start, and success of the cancel
	gotCancelReply := false
	gotStartCancelled := false
	for i := 0; i < 2; i++ {
		select {
		case resp := <-responseCh:
			if resp.CancelResendingEncryptedMessageReply != nil {
				require.Equal(t, thin.ThinClientSuccess, resp.CancelResendingEncryptedMessageReply.ErrorCode)
				gotCancelReply = true
			}
			if resp.StartResendingEncryptedMessageReply != nil {
				require.Equal(t, thin.ThinClientErrorStartResendingCancelled, resp.StartResendingEncryptedMessageReply.ErrorCode)
				gotStartCancelled = true
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for response %d", i)
		}
	}
	require.True(t, gotCancelReply, "should get cancel reply")
	require.True(t, gotStartCancelled, "should get start cancelled")
}

func TestComposeSphinxPacket_SendMessage(t *testing.T) {
	_, client, _, _, _ := setupFullClient(t)

	_, doc := client.CurrentDocument()
	require.NotNil(t, doc)
	require.NotEmpty(t, doc.ServiceNodes)
	serviceIdHash := hash.Sum256(doc.ServiceNodes[0].IdentityKey)

	surbID := &[sphinxConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbID[:])
	require.NoError(t, err)

	request := &Request{
		SendMessage: &thin.SendMessage{
			DestinationIdHash: &serviceIdHash,
			RecipientQueueID:  []byte("echo"),
			Payload:           []byte("ping"),
			WithSURB:          true,
			SURBID:            surbID,
		},
	}

	pkt, surbKey, rtt, err := client.ComposeSphinxPacket(request)
	require.NoError(t, err)
	require.NotEmpty(t, pkt)
	require.NotEmpty(t, surbKey)
	require.True(t, rtt > 0)
}

func TestSendCiphertext(t *testing.T) {
	_, client, _, _, packetCh := setupFullClient(t)

	_, doc := client.CurrentDocument()
	require.NotNil(t, doc)
	serviceIdHash := hash.Sum256(doc.ServiceNodes[0].IdentityKey)

	surbID := &[sphinxConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbID[:])
	require.NoError(t, err)

	request := &Request{
		SendMessage: &thin.SendMessage{
			DestinationIdHash: &serviceIdHash,
			RecipientQueueID:  []byte("echo"),
			Payload:           []byte("test ciphertext send"),
			WithSURB:          true,
			SURBID:            surbID,
		},
	}

	surbKey, rtt, err := client.SendCiphertext(request)
	require.NoError(t, err)
	require.NotEmpty(t, surbKey)
	require.True(t, rtt > 0)

	// Verify packet was sent
	select {
	case pkt := <-packetCh:
		require.NotEmpty(t, pkt)
	case <-time.After(5 * time.Second):
		t.Fatal("packet not received")
	}
}

func TestDaemonSendWithSURB(t *testing.T) {
	d, _, testAppID, responseCh, packetCh := setupFullClient(t)

	_, doc := d.client.CurrentDocument()
	require.NotNil(t, doc)
	serviceIdHash := hash.Sum256(doc.ServiceNodes[0].IdentityKey)

	surbID := &[sphinxConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbID[:])
	require.NoError(t, err)

	messageID := &[MessageIDLength]byte{}
	_, err = rand.Reader.Read(messageID[:])
	require.NoError(t, err)

	request := &Request{
		AppID: testAppID,
		SendMessage: &thin.SendMessage{
			ID:                messageID,
			DestinationIdHash: &serviceIdHash,
			RecipientQueueID:  []byte("echo"),
			Payload:           []byte("test send with SURB"),
			WithSURB:          true,
			SURBID:            surbID,
		},
	}

	d.send(request)

	// Should get a MessageSentEvent
	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.MessageSentEvent)
		require.Equal(t, surbID, resp.MessageSentEvent.SURBID)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for MessageSentEvent")
	}

	// Packet should have been sent
	select {
	case pkt := <-packetCh:
		require.NotEmpty(t, pkt)
	case <-time.After(5 * time.Second):
		t.Fatal("packet not received")
	}

	// Reply descriptor should be stored
	d.replyLock.Lock()
	_, found := d.replies[*surbID]
	d.replyLock.Unlock()
	require.True(t, found, "reply descriptor should be stored")
}

func TestDaemonSendLoopDecoy(t *testing.T) {
	d, _, testAppID, _, packetCh := setupFullClient(t)

	// sendLoopDecoy looks up echo services and creates its own SendMessage
	request := &Request{
		AppID:         testAppID,
		SendLoopDecoy: &SendLoopDecoy{},
	}

	d.sendLoopDecoy(request)

	// Packet should have been sent (echo service exists in mock doc)
	select {
	case pkt := <-packetCh:
		require.NotEmpty(t, pkt)
	case <-time.After(5 * time.Second):
		t.Fatal("packet not received")
	}
}

func TestHandleReply_UnknownSURBID(t *testing.T) {
	d, _, _, _, _ := setupFullClient(t)

	unknownSurbID := &[sphinxConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(unknownSurbID[:])
	require.NoError(t, err)

	// handleReply with unknown SURB ID should return silently (no panic)
	d.handleReply(&sphinxReply{
		surbID:     unknownSurbID,
		ciphertext: []byte("garbage"),
	})
}

func TestHandleReply_DecoyReply(t *testing.T) {
	d, _, _, _, _ := setupFullClient(t)

	surbID := &[sphinxConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbID[:])
	require.NoError(t, err)

	// Register a decoy
	d.replyLock.Lock()
	d.decoys[*surbID] = replyDescriptor{
		surbKey: make([]byte, 32),
	}
	d.replyLock.Unlock()

	// handleReply with decoy SURB ID — decryption will fail but shouldn't panic
	d.handleReply(&sphinxReply{
		surbID:     surbID,
		ciphertext: make([]byte, d.client.geo.PayloadTagLength+d.client.geo.ForwardPayloadLength),
	})

	// Decoy should have been removed from the map
	d.replyLock.Lock()
	_, found := d.decoys[*surbID]
	d.replyLock.Unlock()
	require.False(t, found, "decoy should be removed after handling")
}

func TestCancelResendingCopyCommand_FullPipeline(t *testing.T) {
	d, _, testAppID, responseCh, packetCh := setupFullClient(t)

	// Start a copy command first
	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	kpQueryID := &[thin.QueryIDLength]byte{}
	copy(kpQueryID[:], []byte("cancelcopy-kp-q0"))
	d.newKeypair(&Request{
		AppID:      testAppID,
		NewKeypair: &thin.NewKeypair{QueryID: kpQueryID, Seed: seed},
	})
	var kpResp *Response
	select {
	case kpResp = <-responseCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	startQueryID := &[thin.QueryIDLength]byte{}
	copy(startQueryID[:], []byte("cancelcopy-st-q0"))
	d.startResendingCopyCommand(&Request{
		AppID: testAppID,
		StartResendingCopyCommand: &thin.StartResendingCopyCommand{
			QueryID:  startQueryID,
			WriteCap: kpResp.NewKeypairReply.WriteCap,
		},
	})
	select {
	case <-packetCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for packet")
	}

	// Now cancel the copy command
	writeCapBytes, err := kpResp.NewKeypairReply.WriteCap.MarshalBinary()
	require.NoError(t, err)
	writeCapHash := hash.Sum256(writeCapBytes)

	cancelQueryID := &[thin.QueryIDLength]byte{}
	copy(cancelQueryID[:], []byte("cancelcopy-cn-q0"))
	d.cancelResendingCopyCommand(&Request{
		AppID: testAppID,
		CancelResendingCopyCommand: &thin.CancelResendingCopyCommand{
			QueryID:      cancelQueryID,
			WriteCapHash: &writeCapHash,
		},
	})

	// Should get cancellation response and cancel success
	gotCancel := false
	gotStartCancelled := false
	for i := 0; i < 2; i++ {
		select {
		case resp := <-responseCh:
			if resp.CancelResendingCopyCommandReply != nil {
				require.Equal(t, thin.ThinClientSuccess, resp.CancelResendingCopyCommandReply.ErrorCode)
				gotCancel = true
			}
			if resp.StartResendingCopyCommandReply != nil {
				require.Equal(t, thin.ThinClientErrorStartResendingCancelled, resp.StartResendingCopyCommandReply.ErrorCode)
				gotStartCancelled = true
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for response %d", i)
		}
	}
	require.True(t, gotCancel)
	require.True(t, gotStartCancelled)
}

func TestEgressWorkerDispatches(t *testing.T) {
	d, _, testAppID, responseCh, _ := setupFullClient(t)

	// Start egressWorker
	d.egressCh = make(chan *Request, 10)
	go d.egressWorker()
	t.Cleanup(func() { d.Halt() })

	// Send a NewKeypair request through egressCh
	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("egress-keypair00"))

	d.egressCh <- &Request{
		AppID: testAppID,
		NewKeypair: &thin.NewKeypair{
			QueryID: queryID,
			Seed:    seed,
		},
	}

	// Should get a keypair reply
	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.NewKeypairReply)
		require.Equal(t, thin.ThinClientSuccess, resp.NewKeypairReply.ErrorCode)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for egressWorker response")
	}
}

func TestHandleReply_RegularReply(t *testing.T) {
	d, _, testAppID, responseCh, packetCh := setupFullClient(t)

	_, doc := d.client.CurrentDocument()
	require.NotNil(t, doc)
	serviceIdHash := hash.Sum256(doc.ServiceNodes[0].IdentityKey)

	// Send a message to create a reply descriptor
	surbID := &[sphinxConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbID[:])
	require.NoError(t, err)
	messageID := &[MessageIDLength]byte{}
	_, err = rand.Reader.Read(messageID[:])
	require.NoError(t, err)

	d.send(&Request{
		AppID: testAppID,
		SendMessage: &thin.SendMessage{
			ID:                messageID,
			DestinationIdHash: &serviceIdHash,
			RecipientQueueID:  []byte("echo"),
			Payload:           []byte("test for reply handling"),
			WithSURB:          true,
			SURBID:            surbID,
		},
	})

	// Drain MessageSentEvent and packet
	select {
	case <-responseCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
	select {
	case <-packetCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	// Verify reply descriptor was stored
	d.replyLock.Lock()
	desc, found := d.replies[*surbID]
	d.replyLock.Unlock()
	require.True(t, found)
	require.NotNil(t, desc.surbKey)

	// handleReply with regular reply — decryption will fail (garbage ciphertext)
	// but the descriptor should be removed
	d.handleReply(&sphinxReply{
		surbID:     surbID,
		ciphertext: make([]byte, d.client.geo.PayloadTagLength+d.client.geo.ForwardPayloadLength),
	})

	d.replyLock.Lock()
	_, stillFound := d.replies[*surbID]
	d.replyLock.Unlock()
	require.False(t, stillFound, "reply descriptor should be removed after handling")
}

func TestGetDocumentByEpoch(t *testing.T) {
	_, client, _, _, _ := setupFullClient(t)

	currentEpoch, _, _ := epochtime.Now()

	// Should find the document for current epoch
	doc := client.pki.GetDocumentByEpoch(currentEpoch)
	require.NotNil(t, doc)
	require.Equal(t, currentEpoch, doc.Epoch)

	// Should not find a document for a different epoch
	doc = client.pki.GetDocumentByEpoch(currentEpoch + 100)
	require.Nil(t, doc)
}

func TestComposeSphinxPacket_NoSURB(t *testing.T) {
	_, client, _, _, _ := setupFullClient(t)

	_, doc := client.CurrentDocument()
	require.NotNil(t, doc)
	serviceIdHash := hash.Sum256(doc.ServiceNodes[0].IdentityKey)

	request := &Request{
		SendMessage: &thin.SendMessage{
			DestinationIdHash: &serviceIdHash,
			RecipientQueueID:  []byte("echo"),
			Payload:           []byte("fire and forget"),
			WithSURB:          false,
		},
	}

	pkt, surbKey, rtt, err := client.ComposeSphinxPacket(request)
	require.NoError(t, err)
	require.NotEmpty(t, pkt)
	require.Nil(t, surbKey, "no SURB means no SURB key")
	require.True(t, rtt > 0)
}
