// SPDX-FileCopyrightText: © 2025 Threebit Hacker
// SPDX-License-Identifier: AGPL-3.0-only

// Package bacap provides the Blinded Cryptographic Capability system (BACAP).
//
// BACAP is the Blinded Cryptographic Capability system with
// some resistance against quantum adversaries whose design
// is expounded upon in section 4 of our paper:
//
//	BACAP (Blinding-and-Capability scheme) allows us
//	to deterministically derive a sequence of key pairs using
//	blinding, built upon Ed25519, and suitable for un-
//	linkable messaging. It enables participants to derive box
//	IDs and corresponding encryption keys for independent,
//	single-use boxes using shared symmetric keys.
//
//	A box consists of an ID, a message payload, and a
//	signature over the payload. There are two basic capabili-
//	ties - one that lets a party derive the box IDs and decrypt
//	the messages, and one that additionally lets the holder
//	derive private keys to sign the messages. The signatures
//	are universally veriﬁable, as the box ID for each box
//	doubles as the public key for the signatures.
//
//	In the context of a messaging system, the protocol is
//	used by Alice to send an inﬁnite sequence of messages
//	to Bob, one per box, with Bob using a separate, second
//	instance of the protocol to send messages to Alice.
//
// # Our paper
//
// Echomix: a Strong Anonymity System with Messaging
//
// https://arxiv.org/abs/2501.02933
// https://arxiv.org/pdf/2501.02933
//
// # API Design
//
// Two Capability types:
//
// 1. ReadCap: The Read Capability allows the bearer
// to generate an infinite sequence of verification and decryption keys
// for message boxes in a deterministic sequence.
//
// 2. WriteCap: The Write Capability allows the bearer to
// generate an infinite sequence of signing and encryption keys for
// messages boxes in a deterministic sequence.
//
// Each of the above two capabilities are used with the MessageBoxIndex
// to perform their respective encrypt and sign vs verify and decrypt operations.
//
// Beyond that we have two high-level types: StatefulReader and StatefulWriter,
// which encapsulate all the operational details of advancing state
// after message processing.
//
// # TODOs
//
// This BACAP implementation could possibly be improved, here's a ticket for
// completing the TODO tasks written by its original author:
//
// https://github.com/katzenpost/hpqc/issues/55
package bacap

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"

	"github.com/agl/gcmsiv"
	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/hpqc/util"
)

const (
	// MessageBoxIndexSize is the size in bytes of one MessageBoxIndex struct.
	MessageBoxIndexSize = 8 + 32 + 32 + 32

	// BoxIDSize is the size in bytes of our Box IDs.
	BoxIDSize = ed25519.PublicKeySize

	// SignatureSize is the size in bytes of our signatures.
	SignatureSize = ed25519.SignatureSize

	// Error message constants
	errNextIndexIsNil                   = "next index is nil"
	errNextIndexIsNilCannotParseReply   = "next index is nil, cannot parse reply"
	errInvalidMessageBoxIndexBinarySize = "invalid MessageBoxIndex binary size"
)

// MessageBoxIndex type encapsulates all the various low level cryptographic operations
// such as progressing the HKDF hash object states, encryption/decryption
// of messages, signing and verifying messages.
type MessageBoxIndex struct {
	// i_{0..2^64}: the message counter / index
	Idx64 uint64

	// K_i: blinding value used to derive mailboxID by blinding ed25519 keys
	CurBlindingFactor [32]byte

	// E_i: for encryption message payloads
	CurEncryptionKey [32]byte

	// H_{i+1}, the HKDF key used to calculate MessageBoxIndex for Idx61 + 1
	HKDFState [32]byte // H_i, for computing the next mailbox
}

// ensure we implement encoding.BinaryMarshaler/BinaryUmarshaler
var _ encoding.BinaryMarshaler = (*MessageBoxIndex)(nil)
var _ encoding.BinaryUnmarshaler = (*MessageBoxIndex)(nil)

// NewEmptyMessageBoxIndexFromBytes returns a new MessageBoxIndex from a binary blob.
func NewEmptyMessageBoxIndexFromBytes(b []byte) (*MessageBoxIndex, error) {
	m := NewEmptyMessageBoxIndex()
	err := m.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// NewEmptyMessageBoxIndex returns an empty MessageBoxIndex which can be used
// with the UnmarshalBinary method.
func NewEmptyMessageBoxIndex() *MessageBoxIndex {
	return &MessageBoxIndex{
		Idx64:             0,
		CurBlindingFactor: [32]byte{},
		CurEncryptionKey:  [32]byte{},
		HKDFState:         [32]byte{},
	}
}

// NewMessageBoxIndex returns a new MessageBoxIndex
func NewMessageBoxIndex(rng io.Reader) (*MessageBoxIndex, error) {
	m := MessageBoxIndex{}

	// Pick a random HKDF key for the conversation:
	if ilen, err := io.ReadFull(rng, m.HKDFState[:]); err != nil || ilen != 32 {
		panic(err)
	}

	// Pick a random start index for the conversation.
	// We could start at deterministic index 0, ie 0,
	// but then we would reveal to a later recipient of a capability
	// exactly how many messages preceeded it.
	idx64B := [16]byte{}
	if n, err := io.ReadFull(rng, idx64B[:]); err != nil || n != len(idx64B) {
		panic(err)
	}
	// Since these are not cyclic, overflow of the index denotes the
	// end of usable indices.
	// We pick two integers in 0..2^62-1 and add them together.
	// This ensures an exclusive upper bound of 2^63-2,
	// leaving at least 2^63 usable indices.
	// Sampling two 2^62 bit integers instead of one 2^63 bit biases
	// the distribution towards the middle, reducing the risk of
	// picking a number lower than R which otherwise would be R/2^63,
	// trading it for (R/2^(63-1))^2.
	// The reason is that when we introduce a new party to the conversation,
	// an index of N informs them that we have sent *at most* N messages
	// prior to introducing them, and we would like to minimize the
	// disclosure of such facts.
	idx64B[0] &= 0x2f // 0x2f leaves out the top two bits
	idx64B[8] &= 0x2f
	m.Idx64 = binary.LittleEndian.Uint64(idx64B[:8])
	m.Idx64 += binary.LittleEndian.Uint64(idx64B[8:])
	// believe this is called Irwin-Hall sum.
	// this might be better if normal distribution is what we want:
	// https://en.wikipedia.org/wiki/Box%E2%80%93Muller_transform

	nextIndex, err := m.NextIndex()
	if err != nil {
		return nil, err
	}
	return nextIndex, nil
}

// MarshalBinary returns a binary blob of the given type.
func (m *MessageBoxIndex) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.LittleEndian, m.Idx64)
	if err != nil {
		return nil, err
	}
	for _, field := range [][]byte{
		m.CurBlindingFactor[:],
		m.CurEncryptionKey[:],
		m.HKDFState[:],
	} {
		if _, err := buf.Write(field); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary populates the given MessageBoxIndex from the given serialized blob
// or it returns an error.
func (m *MessageBoxIndex) UnmarshalBinary(data []byte) error {
	if len(data) != MessageBoxIndexSize {
		return errors.New(errInvalidMessageBoxIndexBinarySize)
	}
	m.Idx64 = binary.LittleEndian.Uint64(data[:8])
	copy(m.CurBlindingFactor[:], data[8:40])
	copy(m.CurEncryptionKey[:], data[40:72])
	copy(m.HKDFState[:], data[72:104])
	return nil
}

func (m *MessageBoxIndex) deriveEForContext(ctx []byte) (eICtx [32]byte) {
	hash := func() hash.Hash {
		h, _ := blake2b.New512(nil)
		return h
	}
	hkdfEncEI := hkdf.New(hash, m.CurEncryptionKey[:], ctx, []byte{})
	if n, err := hkdfEncEI.Read(eICtx[:]); err != nil || n != len(eICtx) {
		panic("hkdf error")
	}
	return
}

func (m *MessageBoxIndex) deriveKForContext(ctx []byte) (kICtx [32]byte) {
	hash := func() hash.Hash {
		h, _ := blake2b.New512(nil)
		return h
	}
	hkdfBlindKI := hkdf.New(hash, m.CurBlindingFactor[:], ctx, []byte{})
	if n, err := hkdfBlindKI.Read(kICtx[:]); err != nil || n != len(kICtx) {
		panic("hkdf error")
	}
	return
}

// BoxIDForContext returns a new box ID given a read cap and a cryptographic context.
func (m *MessageBoxIndex) BoxIDForContext(cap *ReadCap, ctx []byte) *ed25519.PublicKey {
	kICtx := m.deriveKForContext(ctx)
	return cap.rootPublicKey.Blind(kICtx[:]) // Produce M_i^ctx = P_R * K_i
}

// SignCiphertextForContext signs the given ciphertext with the
// blinded private key. It also returns the appropriate blinded public
// key which can verify the signature. In our paper that's called the
// Box ID. This method is provided along VerifyCiphertextForContext
// such that you can use BACAP with an alternate encryption scheme.
// BACAP's default encryption scheme uses AES GCM SIV.
func (m *MessageBoxIndex) SignBox(owner *WriteCap, ctx []byte, ciphertext []byte) (mICtx [32]byte, sICtx []byte) {
	kICtx := m.deriveKForContext(ctx)
	mICtx = *(*[32]byte)(owner.rootPublicKey.Blind(kICtx[:]).Bytes())

	// derive blinded private key specific to box index + context and sign the GCM-SIV ciphertext:
	SICtx := owner.rootPrivateKey.Blind(kICtx[:])
	sICtx = SICtx.Sign(ciphertext)
	return // Produce M_i^ctx and s_i^ctx
}

// VerifyCiphertextForContext veridies the given ciphertext using the
// given box ID which is a public key. This method is provided along
// SignCiphertextForContext above, so that you can use BACAP with an
// alternate encryption scheme. BACAP's default encryption scheme
// uses AES GCM SIV.
func (m *MessageBoxIndex) VerifyBox(box [BoxIDSize]byte, ciphertext []byte, sig []byte) (ok bool, err error) {
	var boxPk ed25519.PublicKey
	if err = boxPk.FromBytes(box[:]); err != nil {
		return
	}
	if false == boxPk.Verify(sig, ciphertext) {
		return false, errors.New("signature verification failed")
	}
	return true, nil
}

// EncryptForContext encrypts the given plaintext. The given BoxOwnerCap type and context
// are used here in the encryption key derivation.
func (m *MessageBoxIndex) EncryptForContext(owner *WriteCap, ctx []byte, plaintext []byte) (mICtx [32]byte, cICtx []byte, sICtx []byte) {
	kICtx := m.deriveKForContext(ctx)
	mICtx = *(*[32]byte)(owner.rootPublicKey.Blind(kICtx[:]).Bytes())
	eICtx := m.deriveEForContext(ctx)
	sivenc, err := gcmsiv.NewGCMSIV(eICtx[:])
	if err != nil {
		panic(err) // Can't happen
	}

	// encrypt with AES-GCM-SIV:
	cICtx = sivenc.Seal([]byte{}, mICtx[:16], plaintext, mICtx[:32])

	// derive blinded private key specific to box index + context and sign the GCM-SIV ciphertext:
	SICtx := owner.rootPrivateKey.Blind(kICtx[:])
	sICtx = SICtx.Sign(cICtx)
	return // Produce M_i^ctx, c_i^ctx, s_i^ctx
}

// DecryptForContext decrypts the given ciphertext and verifies the given signature
// using a key derives from the context and other cryptographic materials.
func (m *MessageBoxIndex) DecryptForContext(box [BoxIDSize]byte, ctx []byte, ciphertext []byte, sig []byte) (plaintext []byte, err error) {
	var boxPk ed25519.PublicKey
	if err = boxPk.FromBytes(box[:]); err != nil {
		return
	}
	if false == boxPk.Verify(sig, ciphertext) {
		return nil, errors.New("signature verification failed")
	}
	eICtx := m.deriveEForContext(ctx)
	sivdec, err := gcmsiv.NewGCMSIV(eICtx[:])
	if err != nil {
		return nil, err
	}
	if plaintext, err = sivdec.Open([]byte{}, box[:16], ciphertext, box[:]); err != nil {
		return nil, err
	}
	return
}

// AdvanceIndexTo returns a MessageBoxIndex with it's state advanced to the specified index.
func (m *MessageBoxIndex) AdvanceIndexTo(to uint64) (*MessageBoxIndex, error) {
	if to < m.Idx64 {
		return nil, errors.New("cannot rewind index: target index is less than current index")
	}
	hash := func() hash.Hash {
		h, _ := blake2b.New512(nil)
		return h
	}

	var next MessageBoxIndex
	next.Idx64 = m.Idx64
	next.HKDFState = m.HKDFState
	if to == next.Idx64 {
		return m, nil
	}

	next.CurBlindingFactor = [32]byte{}
	next.CurEncryptionKey = [32]byte{}
	curIdxB := make([]byte, 8)

	for next.Idx64 < to {
		binary.LittleEndian.PutUint64(curIdxB, next.Idx64)
		hkdf := hkdf.New(hash, next.HKDFState[:], nil, curIdxB)
		// Read H_{i+1}, E_i, K_i from the KDF:
		if n, err := hkdf.Read(next.HKDFState[:]); err != nil || n != len(next.HKDFState) {
			panic("hkdf failed, not reachable")
		}
		if n, err := hkdf.Read(next.CurEncryptionKey[:]); err != nil || n != len(next.CurEncryptionKey) {
			panic("hkdf failed, not reachable")
		}
		if n, err := hkdf.Read(next.CurBlindingFactor[:]); err != nil || n != len(next.CurBlindingFactor) {
			panic("hkdf failed, not reachable")
		}
		next.Idx64 = next.Idx64 + 1
	}
	return &next, nil
}

// NextIndex returns a MessageBoxIndex type with it's state advanced to the next box.
func (m *MessageBoxIndex) NextIndex() (*MessageBoxIndex, error) {
	return m.AdvanceIndexTo(m.Idx64 + 1)
}

// DeriveMessageBoxID derives the blinded public key, the mailbox ID, given the root public key.
func (m *MessageBoxIndex) DeriveMessageBoxID(rootPublicKey *ed25519.PublicKey) *ed25519.PublicKey {
	return rootPublicKey.Blind(m.CurBlindingFactor[:])
}

// WriteCap is used by the creator of the message box. It encapsulates
// private key material.
type WriteCap struct {
	// on-disk:
	rootPrivateKey *ed25519.PrivateKey

	// in-memory only:
	rootPublicKey *ed25519.PublicKey

	firstMessageBoxIndex *MessageBoxIndex
}

// WriteCapSize is the size in bytes of a serialized BoxOwnerCap
// not counting it's rootPublicKey field.
const WriteCapSize = ed25519.PrivateKeySize + MessageBoxIndexSize

// ensure we implement encoding.BinaryMarshaler/BinaryUmarshaler
var _ encoding.BinaryMarshaler = (*WriteCap)(nil)
var _ encoding.BinaryUnmarshaler = (*WriteCap)(nil)

// NewWriteCap creates a new BoxOwnerCap
func NewWriteCap(rng io.Reader) (*WriteCap, error) {
	o := WriteCap{}
	sk, pk, err := ed25519.NewKeypair(rng) // S_R, P_R
	if err != nil {
		panic(err)
	}
	o.rootPrivateKey = sk
	o.rootPublicKey = pk
	o.firstMessageBoxIndex, err = NewMessageBoxIndex(rng)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// NewWriteCapFromBytes deserializes a blob into a WriteCap type.
func NewWriteCapFromBytes(data []byte) (*WriteCap, error) {
	cap := NewEmptyWriteCap()
	err := cap.UnmarshalBinary(data)
	if err != nil {
		return nil, err
	}
	return cap, nil
}

// NewEmptyWriteCap returns an empty WriteCap which is can be used
// with the UnmarshalBinary method.
func NewEmptyWriteCap() *WriteCap {
	return &WriteCap{
		rootPrivateKey:       new(ed25519.PrivateKey),
		rootPublicKey:        new(ed25519.PublicKey),
		firstMessageBoxIndex: NewEmptyMessageBoxIndex(),
	}
}

// ReadCap returns our ReadCap
func (o *WriteCap) ReadCap() *ReadCap {
	ret := ReadCap{}
	ret.rootPublicKey = o.rootPublicKey
	// NB: o is the firstIndex that we know about/can read,
	// not necessarily the first index in the conversation:
	ret.firstMessageBoxIndex = o.firstMessageBoxIndex
	return &ret
}

// MarshalBinary returns a binary blob of the BoxOwnerCap type.
// Only serialize the rootPrivateKey. We do not serialize the rootPublicKey
// because it can be derived from the private key.
func (o *WriteCap) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.Write(o.rootPrivateKey.Bytes()); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, o.firstMessageBoxIndex); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary deserializes a blob into the given type.
// Here we derive our public key from the given private key.
func (o *WriteCap) UnmarshalBinary(data []byte) error {
	if len(data) != WriteCapSize {
		return errors.New("invalid BoxOwnerCap binary size")
	}
	o.rootPrivateKey = new(ed25519.PrivateKey)
	err := o.rootPrivateKey.FromBytes(data[:64])
	if err != nil {
		return err
	}
	o.rootPublicKey = o.rootPrivateKey.PublicKey()
	o.firstMessageBoxIndex = &MessageBoxIndex{}
	if err := o.firstMessageBoxIndex.UnmarshalBinary(data[64:]); err != nil {
		return err
	}
	return nil
}

// ReadCap is a read capability can be used to compute BACAP boxes
// and decrypt their message payloads for indices >= firstMessageBoxIndex
type ReadCap struct {
	rootPublicKey *ed25519.PublicKey

	firstMessageBoxIndex *MessageBoxIndex
}

// ReadCapSize is the size in bytes of the ReadCap struct type.
const ReadCapSize = ed25519.PublicKeySize + MessageBoxIndexSize

// ensure we implement encoding.BinaryMarshaler/BinaryUmarshaler
var _ encoding.BinaryMarshaler = (*ReadCap)(nil)
var _ encoding.BinaryUnmarshaler = (*ReadCap)(nil)

func NewEmptyReadCap() *ReadCap {
	return &ReadCap{
		rootPublicKey:        new(ed25519.PublicKey),
		firstMessageBoxIndex: NewEmptyMessageBoxIndex(),
	}
}

// ReadCapFromBytes deserialize the read cap from a blob or return an error.
func ReadCapFromBytes(data []byte) (*ReadCap, error) {
	cap := NewEmptyReadCap()
	err := cap.UnmarshalBinary(data)
	if err != nil {
		return nil, err
	}
	return cap, nil
}

// MarshalBinary returns a binary blob of the given type.
func (u *ReadCap) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.Write(u.rootPublicKey.Bytes()); err != nil {
		return nil, err
	}
	mboxBytes, err := u.firstMessageBoxIndex.MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf.Write(mboxBytes) // error is always nil
	return buf.Bytes(), nil
}

// UnmarshalBinary populates our types fields from the given binary blob.
func (u *ReadCap) UnmarshalBinary(data []byte) error {
	if len(data) != ReadCapSize {
		return errors.New("invalid ReadCap binary size")
	}
	u.rootPublicKey = new(ed25519.PublicKey)
	err := u.rootPublicKey.FromBytes(data[:32])
	if err != nil {
		return err
	}
	u.firstMessageBoxIndex = &MessageBoxIndex{}
	if err := u.firstMessageBoxIndex.UnmarshalBinary(data[32:]); err != nil {
		return err
	}
	return nil
}

// warn about accidental copying of these as they have mutable state:
// https://stackoverflow.com/a/52495303
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

// StatefulReader is a helper type with mutable state for sequential reading
type StatefulReader struct {
	noCopy        noCopy
	Rcap          *ReadCap
	LastInboxRead *MessageBoxIndex
	NextIndex     *MessageBoxIndex
	Ctx           []byte
}

// NewStatefulReader initializes a StatefulReader for the given ReadCap and context.
func NewStatefulReader(urcap *ReadCap, ctx []byte) (*StatefulReader, error) {
	if urcap == nil {
		return nil, errors.New("urcap is nil")
	}
	if ctx == nil {
		return nil, errors.New("ctx is nil")
	}

	// Make a copy of ctx to prevent modification outside this struct
	ctxCopy := make([]byte, len(ctx))
	copy(ctxCopy, ctx)

	sr := &StatefulReader{
		Rcap:          urcap,
		Ctx:           ctxCopy,
		LastInboxRead: urcap.firstMessageBoxIndex,
		NextIndex:     urcap.firstMessageBoxIndex,
	}
	return sr, nil
}

// NewStatefulReaderWithIndex initializes a StatefulReader with a specific next index.
// Note: This creates a reader that starts from the given nextIndex, with LastInboxRead set to nil.
// This means the reader has no history of previously read messages, which is appropriate for
// scenarios where you're resuming from a known checkpoint or starting fresh from a specific index.
func NewStatefulReaderWithIndex(urcap *ReadCap, ctx []byte, nextIndex *MessageBoxIndex) (*StatefulReader, error) {
	if urcap == nil {
		return nil, errors.New("urcap is nil")
	}
	if ctx == nil {
		return nil, errors.New("ctx is nil")
	}
	if nextIndex == nil {
		return nil, errors.New("nextIndex is nil")
	}

	// Make a copy of ctx to prevent modification outside this struct
	ctxCopy := make([]byte, len(ctx))
	copy(ctxCopy, ctx)

	// For a new reader with a specific next index, LastInboxRead is set to nil
	// to indicate that this reader instance has no history of previously read messages.
	// This is semantically correct for resuming from a checkpoint or starting fresh.
	sr := &StatefulReader{
		Rcap:          urcap,
		Ctx:           ctxCopy,
		LastInboxRead: nil,       // No messages read yet with this instance
		NextIndex:     nextIndex, // Set NextIndex to the provided index
	}
	return sr, nil
}

// NewStatefulReaderFromBytes initializes a StatefulReader from a CBOR blob.
func NewStatefulReaderFromBytes(data []byte) (*StatefulReader, error) {
	if data == nil {
		return nil, errors.New("data is nil")
	}
	if len(data) == 0 {
		return nil, errors.New("data is empty")
	}
	sr := &StatefulReader{
		Rcap:          NewEmptyReadCap(),
		LastInboxRead: NewEmptyMessageBoxIndex(),
		NextIndex:     NewEmptyMessageBoxIndex(),
		Ctx:           []byte{},
	}
	err := sr.unmarshal(data)
	if err != nil {
		return nil, err
	}

	// Validate deserialized state
	if sr.Rcap == nil {
		return nil, errors.New("deserialized StatefulReader has nil Urcap")
	}
	if sr.LastInboxRead == nil {
		return nil, errors.New("deserialized StatefulReader has nil LastInboxRead")
	}
	if sr.Ctx == nil {
		return nil, errors.New("deserialized StatefulReader has nil Ctx")
	}
	// Note: NextIndex can be nil (will be computed from LastInboxRead when needed)

	return sr, nil
}

// Marshal uses a CBOR blob to serialize into the StatefulReader.
func (sr *StatefulReader) Marshal() ([]byte, error) {
	return cbor.Marshal(sr)
}

func (sr *StatefulReader) unmarshal(b []byte) error {
	return cbor.Unmarshal(b, sr)
}

// ReadNext gets the next box ID to read.
func (sr *StatefulReader) NextBoxID() (*[BoxIDSize]byte, error) {
	if sr.Ctx == nil {
		return nil, errors.New("next context is nil")
	}

	// Determine the current next index without mutating state
	var nextIndex *MessageBoxIndex
	if sr.NextIndex != nil {
		nextIndex = sr.NextIndex
	} else {
		// Fallback: compute next index from LastInboxRead
		if sr.LastInboxRead == nil {
			return nil, errors.New("both NextIndex and LastInboxRead are nil")
		}
		tmp, err := sr.LastInboxRead.NextIndex()
		if err != nil {
			return nil, err
		}
		nextIndex = tmp
	}

	nextBox := nextIndex.BoxIDForContext(sr.Rcap, sr.Ctx)
	nextBoxID := &[BoxIDSize]byte{}
	copy(nextBoxID[:], nextBox.Bytes())
	return nextBoxID, nil
}

// GetNextMessageIndex returns what the next MessageBoxIndex will be after advancing state.
// This does NOT advance state - it's used for crash consistency planning.
func (sr *StatefulReader) GetNextMessageIndex() (*MessageBoxIndex, error) {
	if sr.NextIndex == nil {
		return nil, errors.New(errNextIndexIsNil)
	}
	return sr.NextIndex.NextIndex()
}

// GetCurrentMessageIndex returns the current MessageBoxIndex.
// This is the index that will be used for the next read.
func (sr *StatefulReader) GetCurrentMessageIndex() *MessageBoxIndex {
	return sr.NextIndex
}

// ParseReply advances state if reading was successful.
func (sr *StatefulReader) DecryptNext(ctx []byte, box [BoxIDSize]byte, ciphertext []byte, sig [SignatureSize]byte) ([]byte, error) {
	if util.CtIsZero(box[:]) {
		return nil, errors.New("empty box, no message received")
	}
	if sr.NextIndex == nil {
		return nil, errors.New(errNextIndexIsNilCannotParseReply)
	}
	nextboxPubKey := sr.NextIndex.BoxIDForContext(sr.Rcap, sr.Ctx)
	if !bytes.Equal(box[:], nextboxPubKey.Bytes()) {
		return nil, errors.New("reply does not match expected box ID")
	}

	// Perform all operations that can fail before modifying any state
	plaintext, err := sr.NextIndex.DecryptForContext(box, ctx, ciphertext, sig[:])
	if err != nil {
		return nil, err
	}

	// Compute the next index before modifying state
	nextIndex, err := sr.NextIndex.NextIndex()
	if err != nil {
		return nil, err
	}

	// Only modify state after all operations have succeeded
	sr.LastInboxRead = sr.NextIndex
	sr.NextIndex = nextIndex

	return plaintext, nil
}

// StatefulWriter maintains sequential state for encrypting messages.
type StatefulWriter struct {
	noCopy        noCopy
	Wcap          *WriteCap
	LastOutboxIdx *MessageBoxIndex
	NextIndex     *MessageBoxIndex
	Ctx           []byte
}

// NewStatefulWriter initializes a StatefulWriter for the given owner and context.
func NewStatefulWriter(owner *WriteCap, ctx []byte) (*StatefulWriter, error) {
	if ctx == nil {
		return nil, errors.New("ctx is nil")
	}

	// Make a copy of ctx to prevent modification outside this struct
	ctxCopy := make([]byte, len(ctx))
	copy(ctxCopy, ctx)

	sw := &StatefulWriter{
		Wcap:          owner,
		Ctx:           ctxCopy,
		LastOutboxIdx: nil,                        // No messages written yet
		NextIndex:     owner.firstMessageBoxIndex, // Start at firstMessage boxIndex (not skipping)
	}
	return sw, nil
}

// NewStatefulWriterWithIndex initializes a StatefulWriter with a specific next index.
func NewStatefulWriterWithIndex(owner *WriteCap, ctx []byte, nextIndex *MessageBoxIndex) (*StatefulWriter, error) {
	if owner == nil {
		return nil, errors.New("owner is nil")
	}
	if ctx == nil {
		return nil, errors.New("ctx is nil")
	}
	if nextIndex == nil {
		return nil, errors.New("nextIndex is nil")
	}

	// Make a copy of ctx to prevent modification outside this struct
	ctxCopy := make([]byte, len(ctx))
	copy(ctxCopy, ctx)

	sw := &StatefulWriter{
		Wcap:          owner,
		Ctx:           ctxCopy,
		LastOutboxIdx: nil,       // No messages written yet with this instance
		NextIndex:     nextIndex, // Start at the provided index
	}
	return sw, nil
}

func NewStatefulWriterFromBytes(data []byte) (*StatefulWriter, error) {
	sw := &StatefulWriter{
		Wcap:          NewEmptyWriteCap(),
		LastOutboxIdx: NewEmptyMessageBoxIndex(),
		NextIndex:     NewEmptyMessageBoxIndex(),
		Ctx:           []byte{},
	}
	err := sw.unmarshal(data)
	if err != nil {
		return nil, err
	}

	// Validate deserialized state
	if sw.Wcap == nil {
		return nil, errors.New("deserialized StatefulWriter has nil Owner")
	}
	if sw.NextIndex == nil {
		return nil, errors.New("deserialized StatefulWriter has nil NextIndex")
	}
	if sw.Ctx == nil {
		return nil, errors.New("deserialized StatefulWriter has nil Ctx")
	}
	// Note: LastOutboxIdx can be nil (no messages written yet)

	return sw, nil
}

// Marshal uses a CBOR blob to serialize into the StatefulWriter.
func (sw *StatefulWriter) Marshal() ([]byte, error) {
	return cbor.Marshal(sw)
}

// Unmarshal uses a CBOR blob to deserialize into the StatefulWriter.
func (sw *StatefulWriter) unmarshal(b []byte) error {
	return cbor.Unmarshal(b, sw)
}

// NextBoxID returns the next mailbox ID for writing.
func (sw *StatefulWriter) NextBoxID() (*ed25519.PublicKey, error) {
	if sw.NextIndex == nil {
		return nil, errors.New(errNextIndexIsNil)
	}
	if sw.Ctx == nil {
		return nil, errors.New("ctx is nil")
	}
	return sw.NextIndex.BoxIDForContext(sw.Wcap.ReadCap(), sw.Ctx), nil
}

// GetNextMessageIndex returns what the next MessageBoxIndex will be after advancing state.
// This does NOT advance state - it's used for crash consistency planning.
func (sw *StatefulWriter) GetNextMessageIndex() (*MessageBoxIndex, error) {
	if sw.NextIndex == nil {
		return nil, errors.New(errNextIndexIsNil)
	}
	return sw.NextIndex.NextIndex()
}

// GetCurrentMessageIndex returns the current MessageBoxIndex.
// This is the index that will be used for the next message.
func (sw *StatefulWriter) GetCurrentMessageIndex() *MessageBoxIndex {
	return sw.NextIndex
}

// PrepareNext encrypts a message WITHOUT advancing state.
// This allows for deferred state advancement until courier acknowledgment.
func (sw *StatefulWriter) PrepareNext(plaintext []byte) (boxID [BoxIDSize]byte, ciphertext []byte, sig []byte, err error) {
	if sw.NextIndex == nil {
		return [BoxIDSize]byte{}, nil, nil, errors.New(errNextIndexIsNil)
	}

	// Encrypt the message without advancing state
	boxID, ciphertext, sig = sw.NextIndex.EncryptForContext(sw.Wcap, sw.Ctx, plaintext)
	return
}

// AdvanceState advances the writer state to the next index.
// This should be called only after courier acknowledgment.
func (sw *StatefulWriter) AdvanceState() error {
	if sw.NextIndex == nil {
		return errors.New(errNextIndexIsNil)
	}

	// Compute the next index
	nextIndex, err := sw.NextIndex.NextIndex()
	if err != nil {
		return err
	}

	// Advance state
	sw.LastOutboxIdx = sw.NextIndex
	sw.NextIndex = nextIndex
	return nil
}

// EncryptNext encrypts a message, advancing state after success.
// This is the original method that immediately advances state.
func (sw *StatefulWriter) EncryptNext(plaintext []byte) (boxID [BoxIDSize]byte, ciphertext []byte, sig []byte, err error) {
	boxID, ciphertext, sig, err = sw.PrepareNext(plaintext)
	if err != nil {
		return
	}
	err = sw.AdvanceState()
	return
}
