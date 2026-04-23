// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand"
	"path/filepath"
	"sync"
	"time"

	"github.com/carlmjohnson/versioninfo"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	hpqcRand "github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/common"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/profiling"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/pigeonhole"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

const (
	// AppIDLength is the length of the application ID in bytes.
	AppIDLength = 16
)

var (
	// errMKEMDecryptionFailed is returned when MKEM decryption fails with all replica keys
	errMKEMDecryptionFailed = errors.New("MKEM decryption failed")

	// errBACAPDecryptionFailed is returned when BACAP decryption or signature verification fails
	errBACAPDecryptionFailed = errors.New("BACAP decryption failed")
)

// replicaError wraps a replica error code from the pigeonhole protocol.
// This allows us to preserve the exact error code while using Go's error handling patterns.
type replicaError struct {
	code uint8
}

func (e *replicaError) Error() string {
	return fmt.Sprintf("replica error code: %d", e.code)
}

type gcReply struct {
	id    *[MessageIDLength]byte
	appID *[AppIDLength]byte
}

type sphinxReply struct {
	surbID     *[sphinxConstants.SURBIDLength]byte
	ciphertext []byte
}

type replyDescriptor struct {
	ID      *[MessageIDLength]byte
	appID   *[AppIDLength]byte
	surbKey []byte
}

type Daemon struct {
	worker.Worker

	logbackend *log.Backend
	log        *logging.Logger

	cfg      *config.Config
	client   *Client
	listener *listener
	egressCh chan *Request

	replies   map[[sphinxConstants.SURBIDLength]byte]replyDescriptor
	decoys    map[[sphinxConstants.SURBIDLength]byte]replyDescriptor
	replyLock *sync.Mutex

	timerQueue *TimerQueue
	ingressCh  chan *sphinxReply
	gcSurbIDCh chan *[sphinxConstants.SURBIDLength]byte

	gcTimerQueue *TimerQueue
	gcReplyCh    chan *gcReply

	arqTimerQueue      *TimerQueue
	arqSurbIDMap       map[[sphinxConstants.SURBIDLength]byte]*ARQMessage
	arqEnvelopeHashMap map[[32]byte]*[sphinxConstants.SURBIDLength]byte // EnvelopeHash -> SURB ID (for cancellation)

	// Cryptographically secure random number generator
	secureRand *mrand.Rand

	haltOnce sync.Once
}

func NewDaemon(cfg *config.Config) (*Daemon, error) {
	// egressSize is the buffer between the Poisson sender and egressWorker.
	// A larger buffer smooths over short hiccups where a mixnet dispatch
	// (Sphinx compose + wire write) runs longer than one Poisson interval,
	// so the sender does not briefly stall and lose pacing under bursts
	// from many clients.
	egressSize := 64
	ingressSize := 200
	// gcBufSize is the buffer for the TimerQueue callback drops used to
	// reclaim reply descriptors and announce message-id garbage collection.
	// The callbacks push with a 15–20s timeout; an unbuffered channel
	// pressed the TimerQueue worker to block whenever the ingressWorker
	// was busy, so under parallel load gc lagged or dropped. Buffered
	// generously — these are short records and the memory cost is trivial.
	gcBufSize := 256
	d := &Daemon{
		cfg:                cfg,
		egressCh:           make(chan *Request, egressSize),
		ingressCh:          make(chan *sphinxReply, ingressSize),
		replies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		decoys:             make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		gcSurbIDCh:         make(chan *[sphinxConstants.SURBIDLength]byte, gcBufSize),
		gcReplyCh:          make(chan *gcReply, gcBufSize),
		replyLock:          new(sync.Mutex),
		arqSurbIDMap:       make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqEnvelopeHashMap: make(map[[32]byte]*[sphinxConstants.SURBIDLength]byte),
		// Initialize cryptographically secure random number generator
		secureRand: hpqcRand.NewMath(),
	}
	err := d.initLogging()
	if err != nil {
		return nil, err
	}
	if err := profiling.Start(d.log); err != nil {
		return nil, fmt.Errorf("failed to start profiling: %w", err)
	}
	return d, nil
}

func (d *Daemon) initLogging() error {
	f := d.cfg.Logging.File
	if !d.cfg.Logging.Disable && d.cfg.Logging.File != "" {
		if !filepath.IsAbs(f) {
			return errors.New("log file path must be absolute path")
		}
	}

	var err error
	d.logbackend, err = log.New(f, d.cfg.Logging.Level, d.cfg.Logging.Disable)
	if err == nil {
		d.log = d.logbackend.GetLogger("katzenpost/client")
		d.log.Noticef("Katzenpost client daemon version: %s", versioninfo.Short())
		d.log.Notice("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")
	}
	return err
}

// Shutdown cleanly shuts down a given Server instance.
func (d *Daemon) Shutdown() {
	d.haltOnce.Do(func() { d.halt() })
}

func (d *Daemon) halt() {
	shutdownStart := time.Now()
	d.log.Info("Starting graceful daemon shutdown")

	// Step 0: Notify all connected thin clients that we're shutting down
	d.log.Debug("Broadcasting ShutdownEvent to thin clients")
	d.listener.broadcastShutdownEvent()

	// Step 1: Stop listener
	listenerStart := time.Now()
	d.log.Debug("Stopping thin client listener")
	d.listener.Shutdown()
	d.log.Infof("Listener stopped in %v", time.Since(listenerStart))

	// Step 2: Stop workers
	workersStart := time.Now()
	d.log.Debug("Stopping workers first to prevent channel deadlocks")
	d.Halt() // shutdown ingressWorker and egressWorker first
	d.log.Infof("Workers stopped in %v", time.Since(workersStart))

	// Step 3: Parallelize timer queue shutdown for faster shutdown
	timerStart := time.Now()
	d.log.Debug("Stopping timer queues in parallel")
	var timerWg sync.WaitGroup
	timerWg.Add(3)

	go func() {
		defer timerWg.Done()
		start := time.Now()
		d.log.Debug("Stopping timerQueue")
		d.timerQueue.Halt()
		d.log.Debugf("timerQueue stopped in %v", time.Since(start))
	}()

	go func() {
		defer timerWg.Done()
		start := time.Now()
		d.log.Debug("Stopping gcTimerQueue")
		d.gcTimerQueue.Halt()
		d.log.Debugf("gcTimerQueue stopped in %v", time.Since(start))
	}()

	go func() {
		defer timerWg.Done()
		start := time.Now()
		d.log.Debug("Stopping arqTimerQueue")
		d.arqTimerQueue.Halt()
		d.log.Debugf("arqTimerQueue stopped in %v", time.Since(start))
	}()

	timerWg.Wait()
	d.log.Infof("All timer queues stopped in %v", time.Since(timerStart))

	// Step 4: Stop client
	clientStart := time.Now()
	d.log.Debug("Stopping client")
	d.client.Shutdown()
	d.log.Infof("Client stopped in %v", time.Since(clientStart))

	d.log.Infof("Daemon shutdown complete in %v", time.Since(shutdownStart))
}

func (d *Daemon) Start() error {
	var err error
	rates := &Rates{}
	if d.cfg.CachedDocument != nil {
		rates = ratesFromPKIDoc(d.cfg.CachedDocument)
	}

	d.client, err = New(d.cfg, d.logbackend)
	if err != nil {
		return err
	}

	d.listener, err = NewListener(d.client, rates, d.egressCh, d.logbackend, d.cleanupForAppID)
	if err != nil {
		return err
	}
	d.listener.SetLocalDispatch(d.dispatchLocal)

	d.cfg.Callbacks = &config.Callbacks{}
	d.cfg.Callbacks.OnACKFn = d.proxyReplies
	d.cfg.Callbacks.OnConnFn = d.listener.updateConnectionStatus
	d.cfg.Callbacks.OnDocumentFn = d.onDocument

	d.timerQueue = NewTimerQueue(func(rawSurbID interface{}) {
		surbID, ok := rawSurbID.(*[sphinxConstants.SURBIDLength]byte)
		if !ok {
			panic("wtf, failed type assertion!")
		}
		select {
		case d.gcSurbIDCh <- surbID:
		case <-d.HaltCh():
			return
		case <-time.After(20 * time.Second):
			d.log.Debugf("Timeout sending to gcSurbIDCh for SURB ID %x", surbID[:])
			return
		}
	})
	d.timerQueue.Start()
	d.arqTimerQueue = NewTimerQueue(func(rawSurbID interface{}) {
		surbID, ok := rawSurbID.(*[sphinxConstants.SURBIDLength]byte)
		if !ok {
			panic("wtf, failed type assertion!")
		}
		// Route to the owning client's per-connection resend queue. The
		// scheduler drains it on a Poisson tick along with fresh sends,
		// so retransmits participate in the same round-robin fairness.
		d.enqueueResend(surbID)
	})
	d.arqTimerQueue.Start()
	d.gcTimerQueue = NewTimerQueue(func(rawGCReply interface{}) {
		myGcReply, ok := rawGCReply.(*gcReply)
		if !ok {
			panic("wtf, failed type assertion!")
		}
		select {
		case d.gcReplyCh <- myGcReply:
		case <-d.HaltCh():
			return
		case <-time.After(15 * time.Second):
			d.log.Debugf("Timeout sending to gcReplyCh for message ID %x", myGcReply.id[:])
			return
		}
	})
	d.gcTimerQueue.Start()

	d.Go(d.ingressWorker)
	d.Go(d.egressWorker)

	err = d.client.Start()
	if err != nil {
		d.log.Warningf("Client start failed (will keep retrying): %s", err)
	}
	return nil
}

func (d *Daemon) onDocument(doc *cpki.Document) {
	slopFactor := 0.8
	pollProvider := time.Duration((1.0 / (doc.LambdaP + doc.LambdaL)) * slopFactor * float64(time.Millisecond))
	d.client.SetPollInterval(pollProvider)
	d.listener.updateFromPKIDoc(doc)
}

func (d *Daemon) proxyReplies(surbID *[sphinxConstants.SURBIDLength]byte, ciphertext []byte) error {
	select {
	case d.ingressCh <- &sphinxReply{
		surbID:     surbID,
		ciphertext: ciphertext}:
	case <-d.HaltCh():
		return nil
	}
	return nil
}

func (d *Daemon) egressWorker() {
	for {
		select {
		case <-d.HaltCh():
			return
		case request := <-d.egressCh:
			d.dispatchMixnet(request)
		}
	}
}

// isLocalRequest reports whether a Request is served entirely by local
// crypto or state mutation and issues no Sphinx send. Local requests run
// inline on the thin client's reader goroutine so they are not throttled by
// the Poisson gate, which exists only to pace mixnet egress.
func isLocalRequest(r *Request) bool {
	return r.NewKeypair != nil ||
		r.EncryptRead != nil ||
		r.EncryptWrite != nil ||
		r.CancelResendingEncryptedMessage != nil ||
		r.CancelResendingCopyCommand != nil ||
		r.NextMessageBoxIndex != nil ||
		r.GetMessageBoxIndexCounter != nil ||
		r.CreateCourierEnvelopesFromPayload != nil ||
		r.CreateCourierEnvelopesFromPayloads != nil ||
		r.CreateCourierEnvelopesFromTombstoneRange != nil
}

// dispatchLocal runs handlers that do no mixnet I/O. Invoked inline from
// the thin client's reader goroutine so key generation, envelope prep, box
// index arithmetic, and ARQ cancellation proceed without waiting on the
// Poisson gate.
func (d *Daemon) dispatchLocal(request *Request) {
	switch {
	case request.NewKeypair != nil:
		d.newKeypair(request)
	case request.EncryptRead != nil:
		d.encryptRead(request)
	case request.EncryptWrite != nil:
		d.encryptWrite(request)
	case request.CancelResendingEncryptedMessage != nil:
		d.cancelResendingEncryptedMessage(request)
	case request.CancelResendingCopyCommand != nil:
		d.cancelResendingCopyCommand(request)
	case request.NextMessageBoxIndex != nil:
		d.nextMessageBoxIndex(request)
	case request.GetMessageBoxIndexCounter != nil:
		d.getMessageBoxIndexCounter(request)
	case request.CreateCourierEnvelopesFromPayload != nil:
		d.createCourierEnvelopesFromPayload(request)
	case request.CreateCourierEnvelopesFromPayloads != nil:
		d.createCourierEnvelopesFromPayloads(request)
	case request.CreateCourierEnvelopesFromTombstoneRange != nil:
		d.createCourierEnvelopesFromTombstoneRange(request)
	default:
		panic("dispatchLocal: request is not a local-only variant")
	}
}

// dispatchMixnet runs handlers that issue a Sphinx send. Invoked by the
// egressWorker on each Poisson tick, so these remain fairly rate-limited
// across all connected clients.
func (d *Daemon) dispatchMixnet(request *Request) {
	switch {
	case request.ResendARQ != nil:
		d.arqDoResend(request.ResendARQ)
	case request.SendLoopDecoy != nil:
		d.sendLoopDecoy(request)
	case request.SendMessage != nil:
		d.send(request)
	case request.StartResendingEncryptedMessage != nil:
		d.startResendingEncryptedMessage(request)
	case request.StartResendingCopyCommand != nil:
		d.startResendingCopyCommand(request)
	default:
		panic("dispatchMixnet: request is not a mixnet-bound variant")
	}
}

func (d *Daemon) ingressWorker() {
	for {
		select {
		case <-d.HaltCh():
			return
		case mygcreply := <-d.gcReplyCh:
			response := &Response{
				AppID: mygcreply.appID,
				MessageIDGarbageCollected: &thin.MessageIDGarbageCollected{
					MessageID: mygcreply.id,
				},
			}
			conn := d.listener.getConnection(mygcreply.appID)
			if conn == nil {
				if d.listener.queueReplyForDisconnected(mygcreply.appID, response) {
					continue
				}
				d.log.Errorf("no connection associated with AppID %x", mygcreply.appID[:])
				continue
			}
			err := conn.sendResponse(response)
			if err != nil {
				d.log.Errorf("failed to send Response: %s", err)
			}
		case surbID := <-d.gcSurbIDCh:
			d.replyLock.Lock()
			delete(d.replies, *surbID)
			delete(d.decoys, *surbID)
			d.replyLock.Unlock()
		case reply := <-d.ingressCh:
			d.handleReply(reply)
		}
	}
}

func (d *Daemon) handleReply(reply *sphinxReply) {
	isReply := false
	isARQReply := false
	isDecoy := false
	desc := replyDescriptor{}
	arqMessage := &ARQMessage{}

	d.replyLock.Lock()
	myReplyDescriptor, isReply := d.replies[*reply.surbID]
	myDecoyDescriptor, isDecoy := d.decoys[*reply.surbID]
	arqMessage, isARQReply = d.arqSurbIDMap[*reply.surbID]
	d.replyLock.Unlock()

	switch {
	case isReply:
		desc = myReplyDescriptor
		d.replyLock.Lock()
		delete(d.replies, *reply.surbID)
		d.replyLock.Unlock()
	case isDecoy:
		desc = myDecoyDescriptor
		d.replyLock.Lock()
		delete(d.decoys, *reply.surbID)
		d.replyLock.Unlock()
	case isARQReply:
		peeked := d.arqTimerQueue.Peek()
		if peeked != nil {
			peekSurbId := peeked.Value.(*[sphinxConstants.SURBIDLength]byte)
			if hmac.Equal(arqMessage.SURBID[:], peekSurbId[:]) {
				d.arqTimerQueue.Pop()
			}
		}
		d.replyLock.Lock()
		delete(d.arqSurbIDMap, *reply.surbID)
		if arqMessage.EnvelopeHash != nil {
			delete(d.arqEnvelopeHashMap, *arqMessage.EnvelopeHash)
		}
		d.replyLock.Unlock()

		d.handlePigeonholeARQReply(arqMessage, reply)
		return
	default:
		return
	}

	surbPayload, err := d.client.sphinx.DecryptSURBPayload(reply.ciphertext, desc.surbKey)
	if err != nil {
		d.log.Debugf("SURB reply decryption error: %s", err.Error())
		return
	}

	// XXX FIXME consume statistics on our loop decoys for n-1 detection
	if isDecoy {
		return
	}

	// Legacy API reply
	response := &Response{
		AppID: desc.appID,
		MessageReplyEvent: &thin.MessageReplyEvent{
			MessageID: desc.ID,
			SURBID:    reply.surbID,
			Payload:   surbPayload,
			ErrorCode: thin.ThinClientSuccess,
		},
	}
	conn := d.listener.getConnection(desc.appID)
	if conn == nil {
		if d.listener.queueReplyForDisconnected(desc.appID, response) {
			return
		}
		d.log.Errorf("no connection associated with AppID %x", desc.appID[:])
		return
	}
	conn.sendResponse(response)
}

// decryptMKEMEnvelope decrypts the MKEM envelope and returns the inner message
// tryDecryptMKEMWithReplicas attempts MKEM decryption using each replica's public key
// in order, returning the decrypted payload and the replica number that succeeded.
func tryDecryptMKEMWithReplicas(
	mkemScheme *mkem.Scheme,
	privateKey nike.PrivateKey,
	envelope []byte,
	replicaNums []uint8,
	replicaPubKeys map[uint8]nike.PublicKey,
) ([]byte, uint8, error) {
	for _, replicaNum := range replicaNums {
		pubKey, ok := replicaPubKeys[replicaNum]
		if !ok {
			continue
		}
		decrypted, err := mkemScheme.DecryptEnvelope(privateKey, pubKey, envelope)
		if err != nil {
			continue
		}
		return decrypted, replicaNum, nil
	}
	return nil, 0, errMKEMDecryptionFailed
}


func (d *Daemon) decryptMKEMEnvelope(env *pigeonhole.CourierEnvelopeReply, envelopeDesc *EnvelopeDescriptor, privateKey nike.PrivateKey) (*pigeonhole.ReplicaMessageReplyInnerMessage, error) {
	mkemPrivateKeyBytes, _ := privateKey.MarshalBinary()
	fmt.Printf("BOB DECRYPTS WITH MKEM KEY: %x\n", mkemPrivateKeyBytes[:16]) // First 16 bytes for brevity

	_, doc := d.client.CurrentDocument()
	if doc == nil {
		d.log.Errorf("no pki doc found")
		return nil, fmt.Errorf("no pki doc found")
	}

	// EnvelopeDescriptor.Epoch already contains the replica epoch
	replicaEpoch := envelopeDesc.Epoch

	// Resolve replica public keys from the PKI document
	replicaPubKeys := make(map[uint8]nike.PublicKey)
	for _, replicaNum := range envelopeDesc.ReplicaNums {
		desc, err := replicaCommon.ReplicaNum(replicaNum, doc)
		if err != nil {
			d.log.Errorf("MKEM DECRYPT: no replicaNum:%v in doc:%v", replicaNum, doc)
			continue
		}
		replicaPubKeyBytes, ok := desc.EnvelopeKeys[replicaEpoch]
		if !ok || len(replicaPubKeyBytes) == 0 {
			d.log.Errorf("MKEM DECRYPT: no usable replicaPubKeyBytes in replicaEpoch:%v", replicaEpoch)
			continue
		}
		replicaPubKey, err := replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(replicaPubKeyBytes)
		if err != nil {
			d.log.Errorf("MKEM DECRYPT: can't parse replicaPubKey: %v", err)
			continue
		}
		replicaPubKeys[replicaNum] = replicaPubKey
	}

	// Try decryption with each replica's key
	rawInnerMsg, replicaNum, err := tryDecryptMKEMWithReplicas(
		replicaCommon.MKEMNikeScheme, privateKey, env.Payload,
		envelopeDesc.ReplicaNums[:], replicaPubKeys,
	)
	if err != nil {
		d.log.Errorf("MKEM DECRYPT FAILED with all possible replicas")
		return nil, err
	}
	d.log.Debugf("MKEM DECRYPT: successfully decrypted with replicaNum:%v", replicaNum)
	innerMsg, err := pigeonhole.ParseReplicaMessageReplyInnerMessage(rawInnerMsg)
	if err != nil {
		d.log.Errorf("failed to unmarshal inner message: %s %v", err, rawInnerMsg)
		return nil, fmt.Errorf("failed to unmarshal inner message: %s", err)
	}

	return innerMsg, nil
}

func (d *Daemon) send(request *Request) {
	var surbKey []byte
	var rtt time.Duration
	var err error
	var now time.Time

	surbKey, rtt, err = d.client.SendCiphertext(request)
	if err != nil {
		d.log.Debugf("SendCiphertext error: %s", err.Error())
	}

	// Check if this is a request with SURB
	var withSURB bool
	var surbID *[sphinxConstants.SURBIDLength]byte
	var messageID *[MessageIDLength]byte
	var isLoopDecoy bool

	if request.SendMessage != nil {
		withSURB = request.SendMessage.WithSURB
		surbID = request.SendMessage.SURBID
		messageID = request.SendMessage.ID
		isLoopDecoy = (request.SendLoopDecoy != nil)
	}

	if withSURB {
		now = time.Now()
		// XXX  this is too aggressive, and must be at least the fetchInterval + rtt + some slopfactor to account for path delays

		fetchInterval := d.client.GetPollInterval()
		slop := time.Second
		duration := rtt + fetchInterval + slop
		replyArrivalTime := now.Add(duration)

		d.timerQueue.Push(uint64(replyArrivalTime.UnixNano()), surbID)

		if !isLoopDecoy {
			incomingConn := d.listener.getConnection(request.AppID)
			if incomingConn != nil {
				var errStr string
				if err != nil {
					errStr = err.Error()
				}
				response := &Response{
					AppID: request.AppID,
					MessageSentEvent: &thin.MessageSentEvent{
						MessageID: messageID,
						SURBID:    surbID,
						SentAt:    now,
						ReplyETA:  rtt,
						Err:       errStr,
					},
				}
				err = incomingConn.sendResponse(response)
				if err != nil {
					d.log.Errorf("failed to send Response: %s", err)
				}
			}
		}
	}

	d.replyLock.Lock()
	if isLoopDecoy {
		d.decoys[*surbID] = replyDescriptor{
			appID:   request.AppID,
			surbKey: surbKey,
		}
		d.replyLock.Unlock()
		return
	}

	if request.SendMessage != nil && request.SendMessage.SURBID != nil {
		// Old API: store in regular replies (only when a SURB was used)
		d.replies[*request.SendMessage.SURBID] = replyDescriptor{
			ID:      request.SendMessage.ID,
			appID:   request.AppID,
			surbKey: surbKey,
		}
		d.replyLock.Unlock()
		return
	}
	d.replyLock.Unlock()
}

func (d *Daemon) sendLoopDecoy(request *Request) {
	// XXX FIXME consume statistics on our echo decoys for n-1 detection

	_, doc := d.client.CurrentDocument()
	if doc == nil {
		d.log.Warning("sendLoopDecoy: no PKI document available, skipping")
		return
	}
	echoServices := common.FindServices(EchoService, doc)
	if len(echoServices) == 0 {
		d.log.Warning("sendLoopDecoy: no echo services available, skipping")
		return
	}
	echoService := echoServices[d.secureRand.Intn(len(echoServices))]

	serviceIdHash := hash.Sum256(echoService.MixDescriptor.IdentityKey)
	payload := make([]byte, d.client.geo.UserForwardPayloadLength)
	surbID := &[sphinxConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbID[:])
	if err != nil {
		panic(err)

	}

	// Convert to SendMessage for actual sending
	request.SendMessage = &thin.SendMessage{
		Payload:           payload,
		SURBID:            surbID,
		DestinationIdHash: &serviceIdHash,
		RecipientQueueID:  echoService.RecipientQueueID,
		WithSURB:          true,
	}

	d.send(request)
}



// resendQueueFullBackoff is how long enqueueResend waits before re-arming
// the ARQ timer when a client's resendCh is full. Must be short enough to
// preserve responsiveness and long enough that the scheduler has a chance
// to drain the queue on a Poisson tick before we retry.
const resendQueueFullBackoff = 100 * time.Millisecond

// enqueueResend hands a pending ARQ retransmit off to the scheduler by
// routing it to the resend queue of the client that owns the message. The
// scheduler picks it up on a Poisson tick along with new sends, so
// retransmits now share fairly with other clients' traffic.
//
// If the client's resendCh is full, the attempt is re-armed on the ARQ
// timer after a short backoff — never dropped silently, because arqDoResend
// is what re-Pushes the timer on success, and a dropped fire would lose the
// retry forever. If the client is disconnected the enqueue is a no-op;
// cleanupForAppID removes the stale map entry.
func (d *Daemon) enqueueResend(surbID *[sphinxConstants.SURBIDLength]byte) {
	d.replyLock.Lock()
	message, ok := d.arqSurbIDMap[*surbID]
	d.replyLock.Unlock()
	if !ok {
		d.log.Debugf("enqueueResend: SURB ID %x not in arqSurbIDMap, dropping", surbID[:])
		return
	}
	if d.listener == nil {
		d.log.Debugf("enqueueResend: listener nil, dropping SURB ID %x", surbID[:])
		return
	}
	conn := d.listener.getConnection(message.AppID)
	if conn == nil {
		d.log.Debugf("enqueueResend: no live connection for AppID %x, dropping SURB ID %x", message.AppID[:], surbID[:])
		return
	}
	select {
	case conn.resendCh <- surbID:
	default:
		retryAt := time.Now().Add(resendQueueFullBackoff)
		d.log.Debugf("enqueueResend: resendCh full for AppID %x, re-arming SURB ID %x at %v", message.AppID[:], surbID[:], retryAt)
		if d.arqTimerQueue != nil {
			d.arqTimerQueue.Push(uint64(retryAt.UnixNano()), surbID)
		}
	}
}

// rotateARQSurbIDLocked rewires an ARQMessage to use newSurbID for its next
// retransmission, keeping d.arqSurbIDMap and d.arqEnvelopeHashMap in sync.
// The caller MUST hold d.replyLock.
//
// Invariant: after this returns,
// arqEnvelopeHashMap[arqMessage.EnvelopeHash] == arqMessage.SURBID, and
// arqSurbIDMap[arqMessage.SURBID] == arqMessage. All ARQ SURB rotations
// must go through this helper so CancelResendingEncryptedMessage can
// always find the current ARQMessage by EnvelopeHash.
func (d *Daemon) rotateARQSurbIDLocked(
	arqMessage *ARQMessage,
	newSurbID *[sphinxConstants.SURBIDLength]byte,
	surbKey []byte,
	rtt time.Duration,
) {
	if arqMessage.SURBID != nil {
		delete(d.arqSurbIDMap, *arqMessage.SURBID)
	}
	arqMessage.SURBID = newSurbID
	arqMessage.SURBDecryptionKeys = surbKey
	arqMessage.ReplyETA = rtt
	arqMessage.SentAt = time.Now()
	arqMessage.Retransmissions++
	d.arqSurbIDMap[*newSurbID] = arqMessage
	if arqMessage.EnvelopeHash != nil {
		d.arqEnvelopeHashMap[*arqMessage.EnvelopeHash] = newSurbID
	}
}

func (d *Daemon) arqDoResend(surbID *[sphinxConstants.SURBIDLength]byte) {
	d.replyLock.Lock()
	message, ok := d.arqSurbIDMap[*surbID]

	// NOTE(david): if the arqSurbIDMap entry is not found
	// it means that HandleAck was already called with the
	// given SURB ID.
	if !ok {
		d.log.Warningf("SURB ID %x NOT FOUND. Aborting resend.", surbID[:])
		d.replyLock.Unlock()
		return
	}

	// Check if the listener exists (could be nil during shutdown or testing)
	if d.listener == nil {
		d.log.Debugf("ARQ resend: listener is nil, cleaning up SURB ID %x", surbID[:])
		delete(d.arqSurbIDMap, *surbID)
		if message.EnvelopeHash != nil {
			delete(d.arqEnvelopeHashMap, *message.EnvelopeHash)
		}
		d.replyLock.Unlock()
		return
	}

	// Check if the connection still exists before attempting any resend operations.
	// If the connection is gone, clean up and abort - there's no client to receive the response.
	incomingConn := d.listener.getConnection(message.AppID)
	if incomingConn == nil {
		d.log.Debugf("ARQ resend: connection already closed for AppID %x, cleaning up SURB ID %x", message.AppID[:], surbID[:])
		delete(d.arqSurbIDMap, *surbID)
		if message.EnvelopeHash != nil {
			delete(d.arqEnvelopeHashMap, *message.EnvelopeHash)
		}
		d.replyLock.Unlock()
		return
	}

	// Pigeonhole ARQ: retry forever (no MaxRetransmissions check)
	d.log.Debugf("Pigeonhole ARQ resend (attempt %d) for EnvelopeHash %x", message.Retransmissions+1, message.EnvelopeHash[:])

	// Reuse the same courier for retries so the courier's dedup cache stays consistent.
	// Switching couriers can cause a different courier to see BoxAlreadyExists (for writes)
	// or BoxIDNotFound (for reads) and get into an infinite re-dispatch loop.
	destIdHash := message.DestinationIdHash
	recipientQueueID := message.RecipientQueueID

	newsurbID := &[sphinxConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(newsurbID[:])
	if err != nil {
		panic(err)
	}

	// Compose packet using ComposeSphinxPacketForQuery for Pigeonhole
	pkt, k, rtt, err := d.client.ComposeSphinxPacketForQuery(&thin.SendChannelQuery{
		DestinationIdHash: destIdHash,
		RecipientQueueID:  recipientQueueID,
		Payload:           message.Payload,
	}, newsurbID)
	if err != nil {
		d.log.Errorf("ARQ resend: failed to compose packet: %s", err.Error())
		d.replyLock.Unlock()
		return
	}

	d.rotateARQSurbIDLocked(message, newsurbID, k, rtt)
	d.replyLock.Unlock()

	// Check arqTimerQueue is not nil before pushing
	if d.arqTimerQueue == nil {
		d.log.Debugf("ARQ resend: arqTimerQueue is nil, skipping timer push for SURB ID %x", newsurbID[:])
		return
	}

	d.log.Debugf("ARQ resend scheduled for SURB ID %x", newsurbID[:])
	myRtt := message.SentAt.Add(message.ReplyETA)
	myRtt = myRtt.Add(RoundTripTimeSlop)
	priority := uint64(myRtt.UnixNano())
	d.arqTimerQueue.Push(priority, newsurbID)

	err = d.client.SendPacket(pkt)
	if err != nil {
		d.log.Warningf("ARQ resend failure: %s", err)
	}
}

// cleanupForAppID cleans up all daemon state associated with a given App ID.
// This is called when a thin client disconnects to ensure proper cleanup.
func (d *Daemon) cleanupForAppID(appID *[AppIDLength]byte) {
	d.log.Infof("cleanupForAppID: cleaning up state for App ID %x", appID[:])

	cleanedARQ := 0
	cleanedReplies := 0
	cleanedDecoys := 0

	d.replyLock.Lock()
	if d.arqSurbIDMap != nil {
		var envHashesToDrop [][32]byte
		for surbID, message := range d.arqSurbIDMap {
			if message.AppID != nil && *message.AppID == *appID {
				if message.EnvelopeHash != nil {
					envHashesToDrop = append(envHashesToDrop, *message.EnvelopeHash)
				}
				delete(d.arqSurbIDMap, surbID)
				cleanedARQ++
			}
		}
		if d.arqEnvelopeHashMap != nil {
			for _, h := range envHashesToDrop {
				delete(d.arqEnvelopeHashMap, h)
			}
		}
	}
	if d.replies != nil {
		for surbID, desc := range d.replies {
			if desc.appID != nil && *desc.appID == *appID {
				delete(d.replies, surbID)
				cleanedReplies++
			}
		}
	}
	if d.decoys != nil {
		for surbID, desc := range d.decoys {
			if desc.appID != nil && *desc.appID == *appID {
				delete(d.decoys, surbID)
				cleanedDecoys++
			}
		}
	}
	d.replyLock.Unlock()

	if cleanedARQ == 0 && cleanedReplies == 0 && cleanedDecoys == 0 {
		d.log.Debugf("cleanupForAppID: no state found for App ID %x", appID[:])
		return
	}

	d.log.Infof("cleanupForAppID: cleaned %d ARQ, %d replies, %d decoys for App ID %x",
		cleanedARQ, cleanedReplies, cleanedDecoys, appID[:])
}

