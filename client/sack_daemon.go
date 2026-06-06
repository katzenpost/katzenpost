// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"errors"
	"fmt"
	"math"

	"github.com/katzenpost/hpqc/bacap"

	"github.com/katzenpost/katzenpost/client/constants"
	"github.com/katzenpost/katzenpost/client/thin"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/pigeonhole"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// DefaultMaxStreamPayloadBytes is the ceiling on a WriteStream plaintext (and
// a ReadStream result) when the kpclientd config leaves MaxStreamPayloadBytes
// unset. It matches the wire frame limit (thin.MaxMessageSize); an operator who
// wants the daemon to answer oversize requests with a clean
// ThinClientErrorPayloadTooLarge reply (rather than have the frame rejected at
// the transport) sets MaxStreamPayloadBytes to something below the frame.
const DefaultMaxStreamPayloadBytes = 40 * 1024 * 1024

// resolveMaxStreamPayload turns a configured MaxStreamPayloadBytes into the
// effective limit: unset (<= 0) yields the default, and any value above the
// wire frame ceiling is clamped to it, since no larger payload could be
// carried in a single frame regardless.
func resolveMaxStreamPayload(configured int) int {
	if configured <= 0 {
		return DefaultMaxStreamPayloadBytes
	}
	if configured > thin.MaxMessageSize {
		return thin.MaxMessageSize
	}
	return configured
}

// maxStreamPayload returns the effective WriteStream/ReadStream payload ceiling
// for this daemon from its configuration.
func (d *Daemon) maxStreamPayload() int {
	return resolveMaxStreamPayload(d.cfg.MaxStreamPayloadBytes)
}

// sackFallbackWindow is used only when the consensus parameters needed to
// compute the bandwidth-delay-product window are unavailable (no PKI document
// yet, or degenerate rates). A window of one degrades gracefully to the old
// per-box stop-and-wait behaviour rather than risking an unbounded burst.
const sackFallbackWindow = 1

// computeSACKWindow returns the bandwidth-delay-product window: the number of
// boxes to keep in flight so the Poisson send rate is saturated without
// overshoot. The pipe holds one box per send slot that elapses during a round
// trip, so
//
//	W* = ceil( (LambdaP / Mu) * N_hops ) + 1
//
// where the mean per-hop delay is 1/Mu and N_hops is the round-trip count of
// delay-contributing hops. With nrHops the forward Sphinx hop count (gateway +
// mix layers + service), the round trip is 2*nrHops - 1: the gateway is
// traversed on both legs while the service turnaround is traversed once. The
// +1 keeps a box ready to fire on the next send slot while the oldest is still
// in flight. Over-windowing is harmless (throughput plateaus), so we err high.
func computeSACKWindow(lambdaP, mu float64, nrHops int) int {
	if lambdaP <= 0 || mu <= 0 || nrHops <= 0 {
		return sackFallbackWindow
	}
	nHops := 2*nrHops - 1
	bdp := (lambdaP / mu) * float64(nHops)
	w := int(math.Ceil(bdp)) + 1
	if w < 1 {
		return sackFallbackWindow
	}
	return w
}

// defaultSACKWindow returns the bandwidth-delay-product window for the current
// epoch, computed from epoch-stable consensus parameters (LambdaP, Mu) and the
// Sphinx hop count, and cached until the consensus rolls. Used as the window
// when a WriteStream/ReadStream request leaves Window unset.
func (d *Daemon) defaultSACKWindow() int {
	_, doc := d.client.CurrentDocument()
	if doc == nil || d.cfg.SphinxGeometry == nil {
		return sackFallbackWindow
	}

	d.sackWindowMu.Lock()
	defer d.sackWindowMu.Unlock()
	if d.sackWindowCached != 0 && d.sackWindowEpoch == doc.Epoch {
		return d.sackWindowCached
	}
	w := computeSACKWindow(doc.LambdaP, doc.Mu, d.cfg.SphinxGeometry.NrHops)
	d.sackWindowEpoch = doc.Epoch
	d.sackWindowCached = w
	d.log.Debugf("defaultSACKWindow: epoch %d, LambdaP=%v Mu=%v NrHops=%d => window=%d",
		doc.Epoch, doc.LambdaP, doc.Mu, d.cfg.SphinxGeometry.NrHops, w)
	return w
}

// preparedBox holds everything needed to put one box of a SACK payload on the
// wire: the serialized CourierQuery, the descriptor that decrypts its reply,
// and the envelope hash that keys the ARQ maps. For a read box, isRead is set
// and readCap/messageBoxIndex carry the material the daemon needs to decrypt
// the returned payload.
type preparedBox struct {
	messageCiphertext  []byte
	envelopeDescriptor []byte
	envHash            *[32]byte

	isRead          bool
	readCap         *bacap.ReadCap
	messageBoxIndex []byte
}

// sackBoxSend is the daemon-internal request that carries one pre-built ARQ
// write through the Poisson-gated egress path, mirroring how ResendARQ routes
// a retransmit. The egressWorker dispatches it to sackDoBoxSend.
type sackBoxSend struct {
	message *ARQMessage
}

// sackBoxError wraps a thin-client error code surfaced by a failed box so the
// final WriteStreamReply can report the original cause.
type sackBoxError struct {
	code uint8
}

func (e *sackBoxError) Error() string {
	return fmt.Sprintf("SACK box failed with thin error code %d", e.code)
}

// sackErrorToCode maps a controller's terminal error onto a thin-client error
// code for the WriteStreamReply.
func sackErrorToCode(err error) uint8 {
	if err == nil {
		return thin.ThinClientSuccess
	}
	var be *sackBoxError
	if errors.As(err, &be) {
		return be.code
	}
	if errors.Is(err, errSACKCancelled) {
		return thin.ThinClientErrorStartResendingCancelled
	}
	return thin.ThinClientErrorInternalError
}

// writeStream drives a windowed selective-ack write of a whole payload. It
// chunks and encrypts every box up front, then hands the boxes to a
// sackController driven on its own goroutine so neither the reader nor the
// egress worker blocks for the life of the transfer. The single
// WriteStreamReply is sent when every box is acknowledged or the transfer
// fails.
func (d *Daemon) writeStream(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}

	req := request.WriteStream
	if req.QueryID == nil || req.WriteCap == nil || req.StartIndex == nil || len(req.Payload) == 0 {
		d.sendWriteStreamError(request, thin.ThinClientErrorInvalidRequest)
		return
	}
	if limit := d.maxStreamPayload(); len(req.Payload) > limit {
		d.log.Errorf("writeStream: plaintext %d bytes exceeds the %d byte stream limit", len(req.Payload), limit)
		d.sendWriteStreamError(request, thin.ThinClientErrorPayloadTooLarge)
		return
	}
	if d.cfg.PigeonholeGeometry() == nil {
		d.log.Error("writeStream: PigeonholeGeometry is nil")
		d.sendWriteStreamError(request, thin.ThinClientErrorInternalError)
		return
	}
	_, doc := d.client.CurrentDocument()
	if doc == nil {
		d.log.Error("writeStream: no PKI document available")
		d.sendWriteStreamError(request, thin.ThinClientErrorInternalError)
		return
	}

	boxes, nextIndex, err := d.prepareSACKBoxes(req.WriteCap, req.StartIndex, req.Payload, doc)
	if err != nil {
		d.log.Errorf("writeStream: %v", err)
		d.sendWriteStreamError(request, thin.ThinClientErrorInternalError)
		return
	}

	window := req.Window
	if window <= 0 {
		window = d.defaultSACKWindow()
	}
	d.log.Debugf("writeStream: %d boxes, window=%d", len(boxes), window)

	sender := &daemonBoxSender{d: d, appID: request.AppID, queryID: req.QueryID, boxes: boxes}
	ctrl := newSACKController(sender, len(boxes), window)
	sender.ctrl = ctrl

	appID := request.AppID
	queryID := req.QueryID
	boxCount := uint32(len(boxes))
	d.Go(func() {
		runErr := ctrl.run(d.HaltCh())
		c := d.listener.getConnection(appID)
		if c == nil {
			d.log.Debugf("writeStream: connection gone before reply for AppID %x", appID[:])
			return
		}
		c.sendResponse(&Response{
			AppID: appID,
			WriteStreamReply: &thin.WriteStreamReply{
				QueryID:             queryID,
				ErrorCode:           sackErrorToCode(runErr),
				NextMessageBoxIndex: nextIndex,
				BoxCount:            boxCount,
			},
		})
	})
}

// readStream drives a windowed selective-ack read of BoxCount sequential
// boxes. It prepares every read envelope up front, then hands the boxes to a
// sackController on its own goroutine, exactly mirroring writeStream. Each
// box completes when its decrypted payload arrives via the daemon's read FSM;
// the controller reassembles them in order and the single ReadStreamReply
// carries the concatenated payload.
func (d *Daemon) readStream(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}

	req := request.ReadStream
	if req.QueryID == nil || req.ReadCap == nil || req.StartIndex == nil || req.BoxCount == 0 {
		d.sendReadStreamError(request, thin.ThinClientErrorInvalidRequest)
		return
	}
	if d.cfg.PigeonholeGeometry() == nil {
		d.log.Error("readStream: PigeonholeGeometry is nil")
		d.sendReadStreamError(request, thin.ThinClientErrorInternalError)
		return
	}
	maxPlaintext := int64(d.cfg.PigeonholeGeometry().MaxPlaintextPayloadLength)
	if limit := d.maxStreamPayload(); int64(req.BoxCount)*maxPlaintext > int64(limit) {
		d.log.Errorf("readStream: %d boxes would exceed the %d byte stream limit", req.BoxCount, limit)
		d.sendReadStreamError(request, thin.ThinClientErrorPayloadTooLarge)
		return
	}
	_, doc := d.client.CurrentDocument()
	if doc == nil {
		d.log.Error("readStream: no PKI document available")
		d.sendReadStreamError(request, thin.ThinClientErrorInternalError)
		return
	}

	boxes, nextIndex, err := d.prepareSACKReadBoxes(req.ReadCap, req.StartIndex, int(req.BoxCount), doc)
	if err != nil {
		d.log.Errorf("readStream: %v", err)
		d.sendReadStreamError(request, thin.ThinClientErrorInternalError)
		return
	}

	window := req.Window
	if window <= 0 {
		window = d.defaultSACKWindow()
	}
	d.log.Debugf("readStream: %d boxes, window=%d", len(boxes), window)

	sender := &daemonBoxSender{d: d, appID: request.AppID, queryID: req.QueryID, boxes: boxes}
	ctrl := newSACKController(sender, len(boxes), window)
	sender.ctrl = ctrl

	appID := request.AppID
	queryID := req.QueryID
	boxCount := uint32(len(boxes))
	d.Go(func() {
		runErr := ctrl.run(d.HaltCh())
		c := d.listener.getConnection(appID)
		if c == nil {
			d.log.Debugf("readStream: connection gone before reply for AppID %x", appID[:])
			return
		}
		var payload []byte
		if runErr == nil {
			payload = ctrl.payload()
		}
		c.sendResponse(&Response{
			AppID: appID,
			ReadStreamReply: &thin.ReadStreamReply{
				QueryID:             queryID,
				ErrorCode:           sackErrorToCode(runErr),
				Payload:             payload,
				NextMessageBoxIndex: nextIndex,
				BoxCount:            boxCount,
			},
		})
	})
}

func (d *Daemon) sendReadStreamError(request *Request, errorCode uint8) {
	d.sendError(request.AppID, &Response{
		AppID: request.AppID,
		ReadStreamReply: &thin.ReadStreamReply{
			QueryID:   request.ReadStream.QueryID,
			ErrorCode: errorCode,
		},
	})
}

// prepareSACKReadBoxes builds a read envelope for each of count sequential
// boxes starting at startIndex, returning the prepared boxes and the index
// immediately after the last one.
func (d *Daemon) prepareSACKReadBoxes(readCap *bacap.ReadCap, startIndex *bacap.MessageBoxIndex, count int, doc *cpki.Document) ([]*preparedBox, *bacap.MessageBoxIndex, error) {
	boxes := make([]*preparedBox, 0, count)
	idx := startIndex
	for i := 0; i < count; i++ {
		pb, err := d.prepareSACKReadBox(readCap, idx, doc)
		if err != nil {
			return nil, nil, err
		}
		boxes = append(boxes, pb)
		next, err := idx.NextIndex()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to advance message box index: %w", err)
		}
		idx = next
	}
	return boxes, idx, nil
}

// prepareSACKReadBox encrypts a single read query into a serialized
// CourierQuery, the descriptor and box index needed to decrypt its reply, and
// the envelope hash. It mirrors encryptRead's per-box recipe.
func (d *Daemon) prepareSACKReadBox(readCap *bacap.ReadCap, idx *bacap.MessageBoxIndex, doc *cpki.Document) (*preparedBox, error) {
	statefulReader, err := bacap.NewStatefulReaderWithIndex(readCap, constants.PIGEONHOLE_CTX, idx)
	if err != nil {
		return nil, fmt.Errorf("failed to create stateful reader: %w", err)
	}
	boxID, err := statefulReader.NextBoxID()
	if err != nil {
		return nil, fmt.Errorf("failed to get box ID: %w", err)
	}
	msg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 0, // 0 = read
		ReadMsg: &pigeonhole.ReplicaRead{
			BoxID: *boxID,
		},
	}
	courierEnvelope, envPrivKey, err := createEnvelopeFromMessageWithPadding(msg, doc, true, 0, d.cfg.PigeonholeGeometry())
	if err != nil {
		return nil, fmt.Errorf("failed to create envelope: %w", err)
	}
	replicaEpoch := replicaCommon.ConvertNormalToReplicaEpoch(doc.Epoch)
	envDesc := &EnvelopeDescriptor{
		Epoch:       replicaEpoch,
		ReplicaNums: courierEnvelope.IntermediateReplicas,
		EnvelopeKey: envPrivKey.Bytes(),
	}
	descBytes, err := envDesc.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize envelope descriptor: %w", err)
	}
	idxBytes, err := idx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message box index: %w", err)
	}
	courierQuery := &pigeonhole.CourierQuery{
		QueryType: 0, // 0 = envelope
		Envelope:  courierEnvelope,
	}
	return &preparedBox{
		messageCiphertext:  courierQuery.Bytes(),
		envelopeDescriptor: descBytes,
		envHash:            courierEnvelope.EnvelopeHash(),
		isRead:             true,
		readCap:            readCap,
		messageBoxIndex:    idxBytes,
	}, nil
}

func (d *Daemon) sendWriteStreamError(request *Request, errorCode uint8) {
	d.sendError(request.AppID, &Response{
		AppID: request.AppID,
		WriteStreamReply: &thin.WriteStreamReply{
			QueryID:   request.WriteStream.QueryID,
			ErrorCode: errorCode,
		},
	})
}

// prepareSACKBoxes chunks payload at the geometry's box size and encrypts each
// chunk into a courier write envelope, advancing the BACAP writer from
// startIndex so the boxes form one sequential stream. It returns the prepared
// boxes and the index immediately after the last box.
func (d *Daemon) prepareSACKBoxes(writeCap *bacap.WriteCap, startIndex *bacap.MessageBoxIndex, payload []byte, doc *cpki.Document) ([]*preparedBox, *bacap.MessageBoxIndex, error) {
	statefulWriter, err := bacap.NewStatefulWriter(writeCap, []byte(constants.PIGEONHOLE_CTX))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create stateful writer: %w", err)
	}
	statefulWriter.NextIndex = startIndex

	maxPayload := d.cfg.PigeonholeGeometry().MaxPlaintextPayloadLength - 4
	chunks := chunkPayload(payload, maxPayload)
	boxes := make([]*preparedBox, 0, len(chunks))
	for _, chunk := range chunks {
		pb, err := d.prepareSACKBox(statefulWriter, doc, chunk)
		if err != nil {
			return nil, nil, err
		}
		boxes = append(boxes, pb)
	}
	return boxes, statefulWriter.NextIndex, nil
}

// prepareSACKBox encrypts a single chunk into a serialized CourierQuery, the
// envelope descriptor needed to decrypt its reply, and the envelope hash. It
// mirrors encryptWrite's per-box recipe but advances the writer's index.
func (d *Daemon) prepareSACKBox(writer *bacap.StatefulWriter, doc *cpki.Document, chunk []byte) (*preparedBox, error) {
	boxID, ciphertext, sig, err := d.encryptWriteChunk(writer, chunk, true)
	if err != nil {
		return nil, err
	}
	msg := writeInnerMessage(boxID, ciphertext, sig)
	courierEnvelope, envPrivKey, err := createEnvelopeFromMessageWithPadding(msg, doc, false, 0, d.cfg.PigeonholeGeometry())
	if err != nil {
		return nil, fmt.Errorf("failed to create envelope: %w", err)
	}
	replicaEpoch := replicaCommon.ConvertNormalToReplicaEpoch(doc.Epoch)
	envDesc := &EnvelopeDescriptor{
		Epoch:       replicaEpoch,
		ReplicaNums: courierEnvelope.IntermediateReplicas,
		EnvelopeKey: envPrivKey.Bytes(),
	}
	descBytes, err := envDesc.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize envelope descriptor: %w", err)
	}
	courierQuery := &pigeonhole.CourierQuery{
		QueryType: 0, // 0 = envelope
		Envelope:  courierEnvelope,
	}
	return &preparedBox{
		messageCiphertext:  courierQuery.Bytes(),
		envelopeDescriptor: descBytes,
		envHash:            courierEnvelope.EnvelopeHash(),
	}, nil
}

// sackDoBoxSend selects a courier and starts the per-box ARQ. Invoked by the
// egress worker on a Poisson tick, so SACK box sends are rate-limited and
// fairly interleaved with all other client traffic just like fresh sends and
// resends. On any failure to dispatch, the box's completion callback fails the
// transfer.
func (d *Daemon) sackDoBoxSend(bs *sackBoxSend) {
	_, doc := d.client.CurrentDocument()
	if doc == nil {
		d.log.Error("sackDoBoxSend: no PKI document available")
		bs.message.OnComplete(thin.ThinClientErrorInternalError, nil)
		return
	}
	destIdHash, recipientQueueID, err := GetRandomCourier(doc)
	if err != nil {
		d.log.Errorf("sackDoBoxSend: failed to get courier: %s", err)
		bs.message.OnComplete(thin.ThinClientErrorInternalError, nil)
		return
	}
	bs.message.DestinationIdHash = destIdHash
	bs.message.RecipientQueueID = recipientQueueID
	if err := d.arqSend(bs.message, *bs.message.EnvelopeHash); err != nil {
		d.log.Errorf("sackDoBoxSend: %s", err)
		bs.message.OnComplete(thin.ThinClientErrorInternalError, nil)
	}
}

// cancelARQByEnvelopeHash removes any in-flight ARQ for envHash and cancels its
// retry timer. Shared teardown used by the SACK box sender; a no-op if the box
// is not (or no longer) in flight.
func (d *Daemon) cancelARQByEnvelopeHash(envHash *[32]byte) {
	d.lockReply()
	surbID, ok := d.arqEnvelopeHashMap[*envHash]
	var arqMessage *ARQMessage
	if ok && surbID != nil {
		arqMessage = d.arqSurbIDMap[*surbID]
		delete(d.arqSurbIDMap, *surbID)
		delete(d.arqEnvelopeHashMap, *envHash)
	}
	d.replyLock.Unlock()

	if arqMessage != nil && arqMessage.SURBID != nil && d.arqTimerQueue != nil {
		d.arqTimerQueue.Cancel(arqMessage.SURBID)
	}
}

// daemonBoxSender is the live-mixnet boxSender behind a sackController. send
// enqueues a pre-built ARQ write onto the egress path; cancel tears down an
// in-flight box. Box completion arrives asynchronously via the ARQ reply path
// calling the message's OnComplete, wired here to the controller.
type daemonBoxSender struct {
	d       *Daemon
	appID   *[AppIDLength]byte
	queryID *[thin.QueryIDLength]byte
	boxes   []*preparedBox
	ctrl    *sackController
}

func (s *daemonBoxSender) send(index int) error {
	conn := s.d.listener.getConnection(s.appID)
	if conn == nil {
		return errSACKCancelled
	}
	pb := s.boxes[index]
	msg := &ARQMessage{
		MessageType:        ARQMessageTypeEnvelope,
		AppID:              s.appID,
		QueryID:            s.queryID,
		EnvelopeHash:       pb.envHash,
		Payload:            pb.messageCiphertext,
		EnvelopeDescriptor: pb.envelopeDescriptor,
		IsRead:             pb.isRead,
		ReadCap:            pb.readCap,
		MessageBoxIndex:    pb.messageBoxIndex,
		State:              ARQStateWaitingForACK,
		OnComplete: func(errorCode uint8, plaintext []byte) {
			if errorCode != thin.ThinClientSuccess {
				s.ctrl.boxFailed(index, &sackBoxError{code: errorCode})
				return
			}
			s.ctrl.boxDone(index, plaintext)
		},
	}
	select {
	case conn.requestCh <- &Request{AppID: s.appID, SACKBoxSend: &sackBoxSend{message: msg}}:
		return nil
	case <-s.d.HaltCh():
		return errSACKCancelled
	}
}

func (s *daemonBoxSender) cancel(index int) {
	s.d.cancelARQByEnvelopeHash(s.boxes[index].envHash)
}
