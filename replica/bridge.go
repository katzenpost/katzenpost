// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/protocols/mkem"

	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/pigeonhole"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// A bridge joins a Reticulum mesh to this mixnet: a mesh replica on the
// same host pushes every box it stores through this socket and pulls
// boxes the mesh lacks. See the Pigeonhole over Reticulum specification.
//
// Each message is one frame: a big endian u32 length, then the payload.
// A query is a type byte, 0 for a read and 1 for a write, the 32 byte
// Box ID, and for a write the 64 byte signature and the ciphertext (empty
// for a tombstone). A reply is a replica error code, and for a found box
// the signature and the ciphertext.
const (
	bridgeQueryRead  = 0
	bridgeQueryWrite = 1

	// bridgeMaxFrame bounds a frame; a box is a few KB.
	bridgeMaxFrame = 1 << 20

	// bridgeIdleTimeout closes a socket that sends nothing for this long.
	bridgeIdleTimeout = time.Hour
)

// BridgeListener serves the bridge socket.
type BridgeListener struct {
	worker.Worker

	log    *logging.Logger
	server *Server
	l      net.Listener

	// conn carries the handler state the replica's own request handlers
	// expect; the bridge is a local peer with no wire session.
	conn *incomingConn

	closeAllCh chan interface{}
	wg         sync.WaitGroup
}

func newBridgeListener(s *Server, path string) (*BridgeListener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	b := &BridgeListener{
		log:        s.LogBackend().GetLogger("replica bridge"),
		server:     s,
		l:          l,
		closeAllCh: make(chan interface{}),
	}
	b.conn = &incomingConn{
		l:   &Listener{server: s, closeAllCh: b.closeAllCh},
		log: b.log,
		geo: s.cfg.SphinxGeometry,
	}
	b.Go(b.worker)
	return b, nil
}

// Halt stops accepting, closes every bridge connection and waits for them.
func (b *BridgeListener) Halt() {
	b.l.Close()
	b.Worker.Halt()
	close(b.closeAllCh)
	b.wg.Wait()
}

func (b *BridgeListener) worker() {
	for {
		c, err := b.l.Accept()
		if err != nil {
			select {
			case <-b.HaltCh():
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			b.log.Warningf("bridge accept: %v", err)
			continue
		}
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			b.serve(c)
		}()
	}
}

func (b *BridgeListener) serve(c net.Conn) {
	defer c.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-b.closeAllCh:
			c.Close()
		case <-done:
		}
	}()
	for {
		c.SetReadDeadline(time.Now().Add(bridgeIdleTimeout))
		query, err := readBridgeFrame(c)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				b.log.Debugf("bridge read: %v", err)
			}
			return
		}
		if err := writeBridgeFrame(c, b.handle(query)); err != nil {
			b.log.Debugf("bridge write: %v", err)
			return
		}
	}
}

func readBridgeFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > bridgeMaxFrame {
		return nil, fmt.Errorf("bridge: frame length %d out of range", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeBridgeFrame(w io.Writer, p []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(p)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}

func (b *BridgeListener) handle(q []byte) []byte {
	kind, boxID, w, ok := decodeBridgeQuery(q)
	switch {
	case !ok:
		return []byte{pigeonhole.ReplicaErrorInvalidPayload}
	case kind == bridgeQueryRead:
		return encodeBridgeReadReply(b.read(boxID))
	default:
		return []byte{b.write(w)}
	}
}

// decodeBridgeQuery parses a query frame: the kind, the Box ID, and for a
// write the ReplicaWrite it carries. A read of the wrong length, a write
// without a whole signature, and an unknown kind are not ok.
func decodeBridgeQuery(q []byte) (kind byte, boxID *[bacap.BoxIDSize]byte, w *pigeonhole.ReplicaWrite, ok bool) {
	if len(q) < 1+bacap.BoxIDSize {
		return 0, nil, nil, false
	}
	boxID = new([bacap.BoxIDSize]byte)
	copy(boxID[:], q[1:1+bacap.BoxIDSize])
	switch q[0] {
	case bridgeQueryRead:
		if len(q) != 1+bacap.BoxIDSize {
			return 0, nil, nil, false
		}
		return bridgeQueryRead, boxID, nil, true
	case bridgeQueryWrite:
		rest := q[1+bacap.BoxIDSize:]
		if len(rest) < bacap.SignatureSize {
			return 0, nil, nil, false
		}
		w = &pigeonhole.ReplicaWrite{BoxID: *boxID}
		copy(w.Signature[:], rest[:bacap.SignatureSize])
		w.Payload = append([]byte(nil), rest[bacap.SignatureSize:]...)
		w.PayloadLen = uint32(len(w.Payload))
		return bridgeQueryWrite, boxID, w, true
	}
	return 0, nil, nil, false
}

func encodeBridgeReadReply(r *pigeonhole.ReplicaReadReply) []byte {
	out := []byte{r.ErrorCode}
	if r.ErrorCode == pigeonhole.ReplicaSuccess {
		out = append(out, r.Signature[:]...)
		out = append(out, r.Payload...)
	}
	return out
}

func (b *BridgeListener) isShard(shards []*pki.ReplicaDescriptor) (bool, error) {
	myKey, err := b.server.identityPublicKey.MarshalBinary()
	if err != nil {
		return false, err
	}
	for _, sh := range shards {
		if hmac.Equal(sh.IdentityKey, myKey) {
			return true, nil
		}
	}
	return false, nil
}

// write takes a box pushed from the mesh as a replication write from a
// peer would be taken: verify, store if this replica is a shard for the
// box, and dispatch to the shards over the replica links. The reply is
// the local outcome when this replica is a shard, and success otherwise,
// meaning accepted for delivery through the connector's retry queue.
func (b *BridgeListener) write(w *pigeonhole.ReplicaWrite) uint8 {
	s := b.server
	if code := verifyReplicaWrite(w, s.pigeonholeGeo); code != pigeonhole.ReplicaSuccess {
		return code
	}
	doc := s.PKIWorker.LastCachedPKIDocument()
	if doc == nil {
		return pigeonhole.ReplicaErrorInternalError
	}
	shards, err := replicaCommon.GetShards(&w.BoxID, doc)
	if err != nil {
		return pigeonhole.ReplicaErrorReplicationFailed
	}
	mine, err := b.isShard(shards)
	if err != nil {
		return pigeonhole.ReplicaErrorInternalError
	}
	code := pigeonhole.ReplicaSuccess
	if mine {
		code = b.conn.handleReplicaWrite(w).ErrorCode
		if code != pigeonhole.ReplicaSuccess && code != pigeonhole.ReplicaErrorBoxAlreadyExists {
			return code
		}
	}
	s.connector.DispatchReplication(pigeonhole.TrunnelReplicaWriteToWireCommand(w, nil))
	return code
}

// read serves a box the mesh lacks: locally when this replica is a shard
// for it, otherwise through the same proxied read to the shards that an
// intermediate replica performs, including read repair.
func (b *BridgeListener) read(boxID *[bacap.BoxIDSize]byte) *pigeonhole.ReplicaReadReply {
	s := b.server
	fail := func(code uint8) *pigeonhole.ReplicaReadReply {
		return &pigeonhole.ReplicaReadReply{BoxID: *boxID, ErrorCode: code}
	}
	rr := &pigeonhole.ReplicaRead{BoxID: *boxID}
	doc := s.PKIWorker.LastCachedPKIDocument()
	if doc == nil {
		return fail(pigeonhole.ReplicaErrorInternalError)
	}
	shards, err := replicaCommon.GetShards(boxID, doc)
	if err != nil {
		return fail(pigeonhole.ReplicaErrorReplicationFailed)
	}
	mine, err := b.isShard(shards)
	if err != nil {
		return fail(pigeonhole.ReplicaErrorInternalError)
	}
	if mine {
		return b.conn.handleReplicaRead(rr)
	}

	first, err := s.proxyFirstCandidate(len(shards))
	if err != nil {
		return fail(pigeonhole.ReplicaErrorInternalError)
	}
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	nikeScheme := schemes.ByName(s.cfg.ReplicaNIKEScheme)
	scheme := mkem.NewScheme(nikeScheme)
	inner := pigeonhole.ReplicaInnerMessage{ReadMsg: rr}
	blob, err := pigeonhole.PadInnerMessageForEncryption(&inner, s.pigeonholeGeo)
	if err != nil {
		return fail(pigeonhole.ReplicaErrorInternalError)
	}
	result := b.conn.proxyReadSweep(shards, first, replicaEpoch, blob, scheme, nikeScheme)
	if result.readReply == nil {
		if result.bareReply != nil {
			return fail(result.bareReply.ErrorCode)
		}
		return fail(pigeonhole.ReplicaErrorReplicationFailed)
	}
	if len(result.missingBox) > 0 && result.readReply.ErrorCode == pigeonhole.ReplicaSuccess {
		b.conn.readRepair(result.readReply, result.missingBox)
	}
	return result.readReply
}
