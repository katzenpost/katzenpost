// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"bytes"
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/pigeonhole"
	pgeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
)

// newBridgeTestServer builds a server whose PKI document lists this replica
// and one unreachable peer, so every box has this replica as a shard and
// the bridge serves locally.
func newBridgeTestServer(t *testing.T) (*Server, *pgeo.Geometry) {
	t.Helper()
	dataDir := CreateTestTempDir(t, "bridge")
	st := newTestState(t, dataDir)
	s := st.server
	st.initDB()
	t.Cleanup(st.Close)
	s.state = st

	pgeom, err := pgeo.NewGeometryFromSphinx(s.cfg.SphinxGeometry, schemes.ByName(s.cfg.ReplicaNIKEScheme))
	require.NoError(t, err)
	s.pigeonholeGeo = pgeom

	idBlob, err := s.identityPublicKey.MarshalBinary()
	require.NoError(t, err)
	desc := &pki.ReplicaDescriptor{Name: "bridge", ReplicaID: 0, IdentityKey: idBlob, EnvelopeKeys: map[uint64][]byte{}}
	// Sharding needs at least K configured replicas; the peer is never
	// reached, replication to it goes to the mock connector.
	peerKey := make([]byte, len(idBlob))
	_, err = rand.Reader.Read(peerKey)
	require.NoError(t, err)
	peer := &pki.ReplicaDescriptor{Name: "peer", ReplicaID: 1, IdentityKey: peerKey, EnvelopeKeys: map[uint64][]byte{}}
	doc := CreateTestPKIDocument(t, []*pki.ReplicaDescriptor{desc, peer}, nil)
	StoreTestDocument(t, s.PKIWorker, doc)
	return s, pgeom
}

func sealTestBox(t *testing.T, pgeom *pgeo.Geometry, plaintext []byte) (*bacap.WriteCap, *pigeonhole.ReplicaWrite) {
	t.Helper()
	wc, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	pos, err := wc.PositionAt(wc.GetMessageBoxIndex())
	require.NoError(t, err)
	padded, err := pigeonhole.CreatePaddedPayload(plaintext, pgeom.MaxPlaintextPayloadLength+4)
	require.NoError(t, err)
	w, err := pigeonhole.Seal(pos, padded)
	require.NoError(t, err)
	return wc, w
}

func bridgeWriteQuery(w *pigeonhole.ReplicaWrite) []byte {
	q := []byte{bridgeQueryWrite}
	q = append(q, w.BoxID[:]...)
	q = append(q, w.Signature[:]...)
	return append(q, w.Payload...)
}

func bridgeReadQuery(boxID [32]byte) []byte {
	return append([]byte{bridgeQueryRead}, boxID[:]...)
}

func TestBridgeWriteThenRead(t *testing.T) {
	s, pgeom := newBridgeTestServer(t)
	b := &BridgeListener{server: s, log: s.LogBackend().GetLogger("bridge"), closeAllCh: make(chan interface{})}
	b.conn = &incomingConn{l: &Listener{server: s, closeAllCh: b.closeAllCh}, log: b.log, geo: s.cfg.SphinxGeometry}

	_, w := sealTestBox(t, pgeom, []byte("yo what up"))

	// Unknown box reads as not found.
	reply := b.handle(bridgeReadQuery(w.BoxID))
	require.Equal(t, []byte{pigeonhole.ReplicaErrorBoxIDNotFound}, reply)

	// A pushed box is stored; pushing it again is idempotent.
	require.Equal(t, []byte{pigeonhole.ReplicaSuccess}, b.handle(bridgeWriteQuery(w)))
	require.Equal(t, []byte{pigeonhole.ReplicaSuccess}, b.handle(bridgeWriteQuery(w)))

	// It reads back byte for byte.
	reply = b.handle(bridgeReadQuery(w.BoxID))
	require.Equal(t, uint8(pigeonhole.ReplicaSuccess), reply[0])
	require.True(t, bytes.Equal(w.Signature[:], reply[1:65]))
	require.True(t, bytes.Equal(w.Payload, reply[65:]))

	// A forged signature is refused before anything is stored.
	bad := *w
	bad.Signature[0] ^= 1
	require.Equal(t, []byte{pigeonhole.ReplicaErrorInvalidSignature}, b.handle(bridgeWriteQuery(&bad)))

	// A wrong sized payload is refused.
	short := *w
	short.Payload = w.Payload[:len(w.Payload)-1]
	require.Equal(t, []byte{pigeonhole.ReplicaErrorInvalidPayload}, b.handle(bridgeWriteQuery(&short)))
}

func TestBridgeTombstone(t *testing.T) {
	s, pgeom := newBridgeTestServer(t)
	b := &BridgeListener{server: s, log: s.LogBackend().GetLogger("bridge"), closeAllCh: make(chan interface{})}
	b.conn = &incomingConn{l: &Listener{server: s, closeAllCh: b.closeAllCh}, log: b.log, geo: s.cfg.SphinxGeometry}

	wc, w := sealTestBox(t, pgeom, []byte("delete me"))
	require.Equal(t, []byte{pigeonhole.ReplicaSuccess}, b.handle(bridgeWriteQuery(w)))

	pos, err := wc.PositionAt(wc.GetMessageBoxIndex())
	require.NoError(t, err)
	tomb, err := pigeonhole.NewTombstone(pos)
	require.NoError(t, err)
	require.Equal(t, []byte{pigeonhole.ReplicaSuccess}, b.handle(bridgeWriteQuery(tomb)))

	reply := b.handle(bridgeReadQuery(w.BoxID))
	require.Equal(t, []byte{pigeonhole.ReplicaErrorTombstone}, reply)
}

func TestBridgeSocket(t *testing.T) {
	s, pgeom := newBridgeTestServer(t)
	path := filepath.Join(CreateTestTempDir(t, "bridgesock"), "bridge.sock")
	b, err := newBridgeListener(s, path)
	require.NoError(t, err)
	defer b.Halt()

	c, err := net.DialTimeout("unix", path, time.Second)
	require.NoError(t, err)
	defer c.Close()

	_, w := sealTestBox(t, pgeom, []byte("over the socket"))
	require.NoError(t, writeBridgeFrame(c, bridgeWriteQuery(w)))
	reply, err := readBridgeFrame(c)
	require.NoError(t, err)
	require.Equal(t, []byte{pigeonhole.ReplicaSuccess}, reply)

	require.NoError(t, writeBridgeFrame(c, bridgeReadQuery(w.BoxID)))
	reply, err = readBridgeFrame(c)
	require.NoError(t, err)
	require.Equal(t, uint8(pigeonhole.ReplicaSuccess), reply[0])
	require.True(t, bytes.Equal(w.Payload, reply[65:]))

	// Garbage is answered, not fatal to the connection.
	require.NoError(t, writeBridgeFrame(c, []byte{7}))
	reply, err = readBridgeFrame(c)
	require.NoError(t, err)
	require.Equal(t, []byte{pigeonhole.ReplicaErrorInvalidPayload}, reply)
}

func readAnnounce(t *testing.T, c net.Conn) (uint64, []byte) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	f, err := readBridgeFrame(c)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(f), 8+32+64)
	return binary.BigEndian.Uint64(f[:8]), f[8:]
}

func subscribe(t *testing.T, path string, since uint64) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("unix", path, time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	require.NoError(t, writeBridgeFrame(c, binary.BigEndian.AppendUint64([]byte{bridgeQuerySubscribe}, since)))
	return c
}

func TestBridgeStream(t *testing.T) {
	s, pgeom := newBridgeTestServer(t)
	path := filepath.Join(CreateTestTempDir(t, "bridgestream"), "bridge.sock")
	b, err := newBridgeListener(s, path)
	require.NoError(t, err)
	defer b.Halt()

	q, err := net.DialTimeout("unix", path, time.Second)
	require.NoError(t, err)
	defer q.Close()
	push := func(w *pigeonhole.ReplicaWrite) {
		require.NoError(t, writeBridgeFrame(q, bridgeWriteQuery(w)))
		reply, err := readBridgeFrame(q)
		require.NoError(t, err)
		require.Equal(t, []byte{pigeonhole.ReplicaSuccess}, reply)
	}
	box := func(w *pigeonhole.ReplicaWrite) []byte {
		return append(append(append([]byte(nil), w.BoxID[:]...), w.Signature[:]...), w.Payload...)
	}
	cur := currentReplicaEpoch()

	// A box stored before the subscription is replayed from the cursor.
	_, old := sealTestBox(t, pgeom, []byte("before"))
	push(old)
	c := subscribe(t, path, cur)
	ep, got := readAnnounce(t, c)
	require.Equal(t, cur, ep)
	require.Equal(t, box(old), got)

	// A subscription from a later epoch replays nothing but sees new boxes.
	later := subscribe(t, path, cur+1)

	// New boxes and tombstones are announced live.
	wc, w := sealTestBox(t, pgeom, []byte("after"))
	push(w)
	pos, err := wc.PositionAt(wc.GetMessageBoxIndex())
	require.NoError(t, err)
	tomb, err := pigeonhole.NewTombstone(pos)
	require.NoError(t, err)
	push(tomb)
	for _, sub := range []net.Conn{c, later} {
		_, got = readAnnounce(t, sub)
		require.Equal(t, box(w), got)
		_, got = readAnnounce(t, sub)
		require.Equal(t, box(tomb), got)
	}

	// An idempotent rewrite stores nothing new and announces nothing.
	push(old)
	later.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, err = readBridgeFrame(later)
	require.Error(t, err)

	// A hung up stream unsubscribes.
	c.Close()
	later.Close()
	require.Eventually(t, func() bool {
		s.state.storedMu.Lock()
		defer s.state.storedMu.Unlock()
		return len(s.state.storedSubs) == 0
	}, 5*time.Second, 10*time.Millisecond)
}

func TestBridgeStreamFallsBehind(t *testing.T) {
	s, _ := newBridgeTestServer(t)
	ch := s.state.subscribeStored(1)
	s.state.announceStored(1, &pigeonhole.Box{})
	s.state.announceStored(2, &pigeonhole.Box{})
	sb, ok := <-ch
	require.True(t, ok)
	require.Equal(t, uint64(1), sb.epoch)
	_, ok = <-ch
	require.False(t, ok, "a full queue closes the stream")
	s.state.unsubscribeStored(ch) // a second close must not panic
}
