// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/katzenpost/katzenpost/pigeonhole"
	pgeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
)

// The bridge socket vectors shared with pigeonhole_rns, the mesh replica in
// Python: it keeps the same file in its testdata and its test reads it.
type bridgeVectors struct {
	Queries []struct {
		Name       string `json:"name"`
		Kind       byte   `json:"kind"`
		BoxID      string `json:"box_id"`
		Signature  string `json:"signature"`
		Ciphertext string `json:"ciphertext"`
		Payload    string `json:"payload"`
		Frame      string `json:"frame"`
	}
	Replies []struct {
		Name       string `json:"name"`
		Code       uint8  `json:"code"`
		Signature  string `json:"signature"`
		Ciphertext string `json:"ciphertext"`
		Payload    string `json:"payload"`
		Frame      string `json:"frame"`
	}
	Malformed []struct {
		Name    string `json:"name"`
		Payload string `json:"payload"`
	}
	Boxes []struct {
		Name           string `json:"name"`
		CiphertextSize int    `json:"ciphertext_size"`
		BoxID          string `json:"box_id"`
		Signature      string `json:"signature"`
		Ciphertext     string `json:"ciphertext"`
		Expect         uint8  `json:"expect"`
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBridgeSocketVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/bridge_socket_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v bridgeVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	for _, q := range v.Queries {
		payload := unhex(t, q.Payload)
		var framed bytes.Buffer
		if err := writeBridgeFrame(&framed, payload); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(framed.Bytes(), unhex(t, q.Frame)) {
			t.Errorf("%s: frame differs", q.Name)
		}
		back, err := readBridgeFrame(&framed)
		if err != nil || !bytes.Equal(back, payload) {
			t.Errorf("%s: frame does not read back: %v", q.Name, err)
		}
		kind, boxID, w, ok := decodeBridgeQuery(payload)
		if !ok || kind != q.Kind || !bytes.Equal(boxID[:], unhex(t, q.BoxID)) {
			t.Errorf("%s: decoded as kind %d ok=%v", q.Name, kind, ok)
			continue
		}
		if kind == bridgeQueryWrite && (!bytes.Equal(w.Signature[:], unhex(t, q.Signature)) ||
			!bytes.Equal(w.Payload, unhex(t, q.Ciphertext)) || int(w.PayloadLen) != len(w.Payload)) {
			t.Errorf("%s: write fields differ", q.Name)
		}
	}
	for _, r := range v.Replies {
		reply := &pigeonhole.ReplicaReadReply{ErrorCode: r.Code}
		if r.Signature != "" {
			copy(reply.Signature[:], unhex(t, r.Signature))
			reply.Payload = unhex(t, r.Ciphertext)
		}
		var got []byte
		if r.Signature != "" {
			got = encodeBridgeReadReply(reply)
		} else {
			got = []byte{r.Code} // a write's outcome, or a read that found nothing
		}
		if !bytes.Equal(got, unhex(t, r.Payload)) {
			t.Errorf("%s: reply %x, want %s", r.Name, got, r.Payload)
		}
	}
	for _, m := range v.Malformed {
		if _, _, _, ok := decodeBridgeQuery(unhex(t, m.Payload)); ok {
			t.Errorf("%s: accepted", m.Name)
		}
	}
	// What a replica answers a write with: the one verification rule, which
	// the write handler and the bridge share.
	for _, b := range v.Boxes {
		w := &pigeonhole.ReplicaWrite{Payload: unhex(t, b.Ciphertext)}
		copy(w.BoxID[:], unhex(t, b.BoxID))
		copy(w.Signature[:], unhex(t, b.Signature))
		w.PayloadLen = uint32(len(w.Payload))
		geo := &pgeo.Geometry{MaxPlaintextPayloadLength: b.CiphertextSize - 4 - 16} // less the length prefix and the AEAD tag
		if got := verifyReplicaWrite(w, geo); got != b.Expect {
			t.Errorf("%s: code %d, want %d", b.Name, got, b.Expect)
		}
	}
}
