// Package ratchet implements the axolotl ratchet, by Trevor Perrin. See
// https://github.com/trevp/axolotl/wiki.
package ratchet

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"time"

	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"github.com/awnumar/memguard"
	"github.com/ugorji/go/codec"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/sha3"
)

const ()

var cborHandle = new(codec.CborHandle)

// KeyExchange is structure containing the public keys
type KeyExchange struct {
	PublicKey      []byte
	IdentityPublic []byte
	Dh             []byte
	Dh1            []byte
}

// SignedKeyExchange is structure containing the signature data
type SignedKeyExchange struct {
	Signed    []byte
	Signature []byte
}

// MessageKey is structure containing the data associated with the message key
type MessageKey struct {
	Num          uint32
	Key          []byte
	CreationTime int64
}

// SavedKeys is structure containing the saved keys from delayed messages
type SavedKeys struct {
	HeaderKey   []byte
	MessageKeys []*MessageKey
}

// State constains all the data associated with a ratchet
type State struct {
	TheirSigningPublic  []byte
	TheirIdentityPublic []byte
	MySigningPublic     []byte
	MySigningPrivate    []byte
	MyIdentityPrivate   []byte
	MyIdentityPublic    []byte
	SavedKeys           []*SavedKeys
	RootKey             []byte
	SendHeaderKey       []byte
	RecvHeaderKey       []byte
	NextSendHeaderKey   []byte
	NextRecvHeaderKey   []byte
	SendChainKey        []byte
	RecvChainKey        []byte
	SendRatchetPrivate  []byte
	RecvRatchetPublic   []byte
	SendCount           uint32
	RecvCount           uint32
	PrevSendCount       uint32
	Private0            []byte
	Private1            []byte
	Ratchet             bool
}

// savedKey contains a message key and timestamp for a message which has not
// been received. The timestamp comes from the message by which we learn of the
// missing message.
type savedKey struct {
	key       [keySize]byte
	timestamp time.Time
}

// Ratchet stucture contains the per-contact, crypto state.
type Ratchet struct {
	TheirSigningPublic  *memguard.LockedBuffer // 32 bytes long
	TheirIdentityPublic *memguard.LockedBuffer // 32 bytes long

	MySigningPublic  *memguard.LockedBuffer // 32 bytes long
	MySigningPrivate *memguard.LockedBuffer // 64 bytes long

	MyIdentityPrivate *memguard.LockedBuffer // 32 bytes long
	MyIdentityPublic  *memguard.LockedBuffer // 32 bytes long

	// Now is an optional function that will be used to get the current
	// time. If nil, time.Now is used.
	Now func() time.Time

	// rootKey gets updated by the DH ratchet.
	rootKey *memguard.LockedBuffer // 32 bytes long
	// Header keys are used to encrypt message headers.
	sendHeaderKey, recvHeaderKey         *memguard.LockedBuffer // 32 bytes long
	nextSendHeaderKey, nextRecvHeaderKey *memguard.LockedBuffer // 32 bytes long
	// Chain keys are used for forward secrecy updating.
	sendChainKey, recvChainKey            *memguard.LockedBuffer // 32 bytes long
	sendRatchetPrivate, recvRatchetPublic *memguard.LockedBuffer // 32 bytes long
	sendCount, recvCount                  uint32
	prevSendCount                         uint32
	// ratchet is true if we will send a new ratchet value in the next message.
	ratchet bool

	// saved is a map from a header key to a map from sequence number to
	// message key.
	saved map[[keySize]byte]map[uint32]savedKey

	// kxPrivate0 and kxPrivate1 contain curve25519 private values during
	// the key exchange phase. They are not valid once key exchange has
	// completed.
	kxPrivate0, kxPrivate1 *memguard.LockedBuffer

	rand io.Reader
}

func (r *Ratchet) randBytes(buf []byte) {
	if _, err := io.ReadFull(r.rand, buf); err != nil {
		panic(err)
	}
}

// InitRatchet initializes a ratchet struct
func InitRatchet(rand io.Reader) (*Ratchet, error) {
	r := &Ratchet{
		rand:  rand,
		saved: make(map[[keySize]byte]map[uint32]savedKey),
	}

	r.kxPrivate0, _ = memguard.NewBufferFromReader(rand, privateKeySize)
	r.kxPrivate1, _ = memguard.NewBufferFromReader(rand, privateKeySize)

	mySigningPublic, mySigningPrivate, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, errors.New("Failed to initialize the ratchet")
	}

	r.MySigningPublic = memguard.NewBufferFromBytes(mySigningPublic[:])
	r.MySigningPrivate = memguard.NewBufferFromBytes(mySigningPrivate[:])

	var tmpIdentityPrivate, tmpIdentityPublic [privateKeySize]byte
	extra25519.PrivateKeyToCurve25519(&tmpIdentityPrivate, r.MySigningPrivate.ByteArray64())
	r.MyIdentityPrivate = memguard.NewBufferFromBytes(tmpIdentityPrivate[:])

	curve25519.ScalarBaseMult(&tmpIdentityPublic, r.MyIdentityPrivate.ByteArray32())
	r.MyIdentityPublic = memguard.NewBufferFromBytes(tmpIdentityPublic[:])

	// sanity math assertion
	var curve25519Public [publicKeySize]byte
	extra25519.PublicKeyToCurve25519(&curve25519Public, r.MySigningPublic.ByteArray32())

	if !bytes.Equal(curve25519Public[:], r.MyIdentityPublic.ByteArray32()[:]) {
		panic("Failed: Incorrect Public/Private Keys")
	}

	return r, nil
}

// CreateKeyExchange created and add the appropiate fields for the KeyExchange
func (r *Ratchet) CreateKeyExchange() (*SignedKeyExchange, error) {
	kx := &KeyExchange{
		PublicKey:      make([]byte, publicKeySize),
		IdentityPublic: make([]byte, publicKeySize),
	}

	copy(kx.PublicKey, r.MySigningPublic.ByteArray32()[:])
	copy(kx.IdentityPublic, r.MyIdentityPublic.ByteArray32()[:])

	err := r.FillKeyExchange(kx)
	if err != nil {
		return nil, err
	}

	serialized := []byte{}
	enc := codec.NewEncoderBytes(&serialized, cborHandle)
	if err := enc.Encode(kx); err != nil {
		return nil, err
	}

	sig := ed25519.Sign(r.MySigningPrivate.ByteArray64(), serialized)
	return &SignedKeyExchange{
		Signed:    serialized,
		Signature: sig[:],
	}, nil
}

// FillKeyExchange sets elements of kx with key exchange information from the
// ratchet.
func (r *Ratchet) FillKeyExchange(kx *KeyExchange) error {
	if r.kxPrivate0 == nil || r.kxPrivate1 == nil {
		return errors.New("Ratchet: handshake already complete")
	}

	var public0, public1 [publicKeySize]byte
	curve25519.ScalarBaseMult(&public0, r.kxPrivate0.ByteArray32())
	curve25519.ScalarBaseMult(&public1, r.kxPrivate1.ByteArray32())
	kx.Dh = public0[:]
	kx.Dh1 = public1[:]

	return nil
}

// deriveKey takes an HMAC object and a label and calculates out = HMAC(k, label).
func deriveKey(label []byte, h hash.Hash) *memguard.LockedBuffer {
	out := make([]byte, keySize)

	h.Reset()
	h.Write(label)
	n := h.Sum(out[:0])
	if &n[0] != &out[0] {
		panic("Hash function too large")
	}

	dst := memguard.NewBuffer(keySize)
	dst.Copy(out)

	return dst
}

// These constants are used as the label argument to deriveKey to derive
// independent keys from a master key.
var (
	chainKeyLabel      = []byte("chain key")
	headerKeyLabel     = []byte("header key")
	nextHeaderKeyLabel = []byte("next header key")
	rootKeyLabel       = []byte("root key")
	rootKeyUpdateLabel = []byte("root key update")
	messageKeyLabel    = []byte("message key")
	chainKeyStepLabel  = []byte("chain key step")
)

// ProcessKeyExchange processes the data of a KeyExchange
func (r *Ratchet) ProcessKeyExchange(signedKeyExchange *SignedKeyExchange) error {
	var sig [signatureSize]byte
	if len(signedKeyExchange.Signature) != len(sig) {
		return errors.New("invalid signature length")
	}
	copy(sig[:], signedKeyExchange.Signature)

	kx := new(KeyExchange)
	err := codec.NewDecoderBytes(signedKeyExchange.Signed, cborHandle).Decode(&kx)
	if err != nil {
		return err
	}

	if len(kx.PublicKey) != publicKeySize {
		return errors.New("Invalid public key")
	}

	if r.TheirSigningPublic == nil {
		r.TheirSigningPublic = memguard.NewBuffer(publicKeySize)
	}

	r.TheirSigningPublic.Wipe()
	r.TheirSigningPublic.Copy(kx.PublicKey)

	if !ed25519.Verify(r.TheirSigningPublic.ByteArray32(), signedKeyExchange.Signed, &sig) {
		return errors.New("Invalid signature")
	}

	var ed25519Public, curve25519Public [publicKeySize]byte
	copy(ed25519Public[:], kx.PublicKey)
	extra25519.PublicKeyToCurve25519(&curve25519Public, &ed25519Public)
	if !bytes.Equal(curve25519Public[:], kx.IdentityPublic[:]) {
		return errors.New("Ratchet: key exchange public key and identity public key must be isomorphically equal")
	}

	if len(kx.PublicKey) != r.TheirSigningPublic.Size() {
		return errors.New("Invalid public key")
	}

	r.TheirSigningPublic.Wipe()
	r.TheirSigningPublic.Copy(kx.PublicKey)

	if publicKeySize != len(kx.IdentityPublic) {
		return errors.New("Invalid public identity key")
	}

	if r.TheirIdentityPublic == nil {
		r.TheirIdentityPublic = memguard.NewBuffer(publicKeySize)
	}

	r.TheirIdentityPublic.Wipe()
	r.TheirIdentityPublic.Copy(kx.IdentityPublic)

	return r.CompleteKeyExchange(kx)
}

// CompleteKeyExchange takes a KeyExchange message from the other party and
// establishes the ratchet.
func (r *Ratchet) CompleteKeyExchange(kx *KeyExchange) error {
	if r.kxPrivate0 == nil {
		return errors.New("Ratchet: handshake already complete")
	}

	var public0 [publicKeySize]byte
	curve25519.ScalarBaseMult(&public0, r.kxPrivate0.ByteArray32())

	if len(kx.Dh) != len(public0) {
		return errors.New("Ratchet: peer's key exchange is invalid")
	}

	if len(kx.Dh1) != len(public0) {
		return errors.New("Ratchet: peer using old-form key exchange")
	}

	var amAlice bool
	switch bytes.Compare(public0[:], kx.Dh) {
	case -1:
		amAlice = true
	case 1:
		amAlice = false
	case 0:
		return errors.New("Ratchet: peer echoed our own DH values back")
	}

	var theirDH [publicKeySize]byte
	copy(theirDH[:], kx.Dh)

	keyMaterial := make([]byte, 0, publicKeySize*5)
	var sharedKey [sharedKeySize]byte
	curve25519.ScalarMult(&sharedKey, r.kxPrivate0.ByteArray32(), &theirDH)
	keyMaterial = append(keyMaterial, sharedKey[:]...)

	if amAlice {
		curve25519.ScalarMult(&sharedKey, r.MyIdentityPrivate.ByteArray32(), &theirDH)
		keyMaterial = append(keyMaterial, sharedKey[:]...)
		curve25519.ScalarMult(&sharedKey, r.kxPrivate0.ByteArray32(), r.TheirIdentityPublic.ByteArray32())
		keyMaterial = append(keyMaterial, sharedKey[:]...)
	} else {
		curve25519.ScalarMult(&sharedKey, r.kxPrivate0.ByteArray32(), r.TheirIdentityPublic.ByteArray32())
		keyMaterial = append(keyMaterial, sharedKey[:]...)
		curve25519.ScalarMult(&sharedKey, r.MyIdentityPrivate.ByteArray32(), &theirDH)
		keyMaterial = append(keyMaterial, sharedKey[:]...)
	}

	h := hmac.New(sha3.New256, keyMaterial)
	r.rootKey = deriveKey(rootKeyLabel, h)
	wipe(keyMaterial)

	r.sendHeaderKey = memguard.NewBuffer(keySize)
	r.recvHeaderKey = memguard.NewBuffer(keySize)
	r.nextSendHeaderKey = memguard.NewBuffer(keySize)
	r.nextRecvHeaderKey = memguard.NewBuffer(keySize)
	r.sendRatchetPrivate = memguard.NewBuffer(keySize)
	r.recvRatchetPublic = memguard.NewBuffer(keySize)
	r.sendChainKey = memguard.NewBuffer(keySize)
	r.recvChainKey = memguard.NewBuffer(keySize)

	if amAlice {
		r.recvHeaderKey = deriveKey(headerKeyLabel, h)
		r.nextSendHeaderKey = deriveKey(nextHeaderKeyLabel, h)
		r.nextRecvHeaderKey = deriveKey(nextHeaderKeyLabel, h)
		r.recvChainKey = deriveKey(chainKeyLabel, h)
		r.recvRatchetPublic.Copy(kx.Dh1)
	} else {
		r.sendHeaderKey = deriveKey(headerKeyLabel, h)
		r.nextRecvHeaderKey = deriveKey(nextHeaderKeyLabel, h)
		r.nextSendHeaderKey = deriveKey(nextHeaderKeyLabel, h)
		r.sendChainKey = deriveKey(chainKeyLabel, h)
		r.sendRatchetPrivate.Copy(r.kxPrivate1.ByteArray32()[:])
	}

	r.ratchet = amAlice

	r.kxPrivate0.Melt()
	r.kxPrivate1.Melt()
	r.kxPrivate0.Wipe()
	r.kxPrivate1.Wipe()

	defer r.kxPrivate0.Freeze()
	defer r.kxPrivate1.Freeze()

	return nil
}

// Encrypt acts like append() but appends an encrypted version of msg to out.
func (r *Ratchet) Encrypt(out, msg []byte) []byte {
	if r.ratchet {
		r.sendRatchetPrivate, _ = memguard.NewBufferFromReader(r.rand, keySize)
		r.sendHeaderKey.Melt()
		defer r.sendHeaderKey.Freeze()
		r.sendHeaderKey.Copy(r.nextSendHeaderKey.ByteArray32()[:])

		var sharedKey, keyMaterial [sharedKeySize]byte
		curve25519.ScalarMult(&sharedKey, r.sendRatchetPrivate.ByteArray32(), r.recvRatchetPublic.ByteArray32())

		// TODO: define as a separate function
		sha := sha3.New256()
		sha.Write(rootKeyUpdateLabel)
		sha.Write(r.rootKey.ByteArray32()[:])
		sha.Write(sharedKey[:])
		sha.Sum(keyMaterial[:0])
		h := hmac.New(sha3.New256, keyMaterial[:])

		r.rootKey = deriveKey(rootKeyLabel, h)
		r.nextSendHeaderKey = deriveKey(headerKeyLabel, h)
		r.sendChainKey = deriveKey(chainKeyLabel, h)
		r.prevSendCount, r.sendCount = r.sendCount, 0
		r.ratchet = false
	}

	var messageKey *memguard.LockedBuffer // 32 bytes long
	h := hmac.New(sha3.New256, r.sendChainKey.ByteArray32()[:])
	messageKey = deriveKey(messageKeyLabel, h)
	r.sendChainKey = deriveKey(chainKeyStepLabel, h)

	var sendRatchetPublic [publicKeySize]byte
	curve25519.ScalarBaseMult(&sendRatchetPublic, r.sendRatchetPrivate.ByteArray32())

	var header [headerSize]byte
	var headerNonce, messageNonce [nonceSize]byte
	r.randBytes(headerNonce[:])
	r.randBytes(messageNonce[:])

	binary.LittleEndian.PutUint32(header[0:4], r.sendCount)
	binary.LittleEndian.PutUint32(header[4:8], r.prevSendCount)
	copy(header[8:], sendRatchetPublic[:])
	copy(header[nonceInHeaderOffset:], messageNonce[:])
	out = append(out, headerNonce[:]...)
	out = secretbox.Seal(out, header[:], &headerNonce, r.sendHeaderKey.ByteArray32())
	r.sendCount++

	return secretbox.Seal(out, msg, &messageNonce, messageKey.ByteArray32())
}

// trySavedKeys tries to decrypt the ciphertext using keys saved for delayed messages.
func (r *Ratchet) trySavedKeys(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < sealedHeaderSize {
		return nil, errors.New("Ratchet: header too small to be valid")
	}

	sealedHeader := ciphertext[:sealedHeaderSize]
	var nonce [nonceSize]byte
	copy(nonce[:], sealedHeader)
	sealedHeader = sealedHeader[len(nonce):]

	for headerKey, messageKeys := range r.saved {
		header, ok := secretbox.Open(nil, sealedHeader, &nonce, &headerKey)
		if !ok {
			continue
		}
		if len(header) != headerSize {
			continue
		}
		msgNum := binary.LittleEndian.Uint32(header[:4])
		msgKey, ok := messageKeys[msgNum]
		if !ok {
			// This is a fairly common case: the message key might
			// not have been saved because it's the next message
			// key.
			return nil, nil
		}

		sealedMessage := ciphertext[sealedHeaderSize:]
		copy(nonce[:], header[nonceInHeaderOffset:])
		msg, ok := secretbox.Open(nil, sealedMessage, &nonce, &msgKey.key)
		if !ok {
			return nil, errors.New("Ratchet: corrupt message")
		}
		delete(messageKeys, msgNum)
		// TODO: weird way to check
		if len(messageKeys) == 0 {
			delete(r.saved, headerKey)
		}
		return msg, nil
	}

	return nil, nil
}

// saveKeys takes a header key, the current chain key, a received message
// number and the expected message number and advances the chain key as needed.
// It returns the message key for given given message number and the new chain
// key. If any messages have been skipped over, it also returns savedKeys, a
// map suitable for merging with r.saved, that contains the message keys for
// the missing messages.
func (r *Ratchet) saveKeys(headerKey, recvChainKey *[receivingChainKeySize]byte, messageNum, receivedCount uint32) (provisionalChainKey, messageKey *memguard.LockedBuffer, savedKeys map[[messageKeySize]byte]map[uint32]savedKey, err error) {
	if messageNum < receivedCount {
		// This is a message from the past, but we didn't have a saved
		// key for it, which means that it's a duplicate message or we
		// expired the save key.
		err = errors.New("Ratchet: duplicate message or message delayed longer than tolerance")
		return
	}

	missingMessages := messageNum - receivedCount
	if missingMessages > maxMissingMessages {
		err = errors.New("Ratchet: message exceeds reordering limit")
		return
	}

	// messageKeys maps from message number to message key.
	var messageKeys map[uint32]savedKey
	var now time.Time
	if missingMessages > 0 {
		messageKeys = make(map[uint32]savedKey)
		if r.Now == nil {
			now = time.Now()
		} else {
			now = r.Now()
		}
	}

	provisionalChainKey = memguard.NewBuffer(keySize)
	provisionalChainKey.Copy(recvChainKey[:])

	for n := receivedCount; n <= messageNum; n++ {
		h := hmac.New(sha3.New256, provisionalChainKey.ByteArray32()[:])
		messageKey = deriveKey(messageKeyLabel, h)
		provisionalChainKey = deriveKey(chainKeyStepLabel, h)

		if n < messageNum {
			messageKeys[n] = savedKey{*messageKey.ByteArray32(), now}
		}
	}

	if messageKeys != nil {
		savedKeys = make(map[[32]byte]map[uint32]savedKey)
		savedKeys[*headerKey] = messageKeys
	}

	return
}

// mergeSavedKeys takes a map of saved message keys from saveKeys and merges it
// into r.saved.
func (r *Ratchet) mergeSavedKeys(newKeys map[[messageKeySize]byte]map[uint32]savedKey) {
	for headerKey, newMessageKeys := range newKeys {
		messageKeys, ok := r.saved[headerKey]
		if !ok {
			r.saved[headerKey] = newMessageKeys
			continue
		}

		for n, messageKey := range newMessageKeys {
			messageKeys[n] = messageKey
		}
	}
}

// isZeroKey returns true if key is all zeros.
func isZeroKey(key *[32]byte) bool {
	var x uint8
	for _, v := range key {
		x |= v
	}

	return x == 0
}

// Decrypt decrypts a message
func (r *Ratchet) Decrypt(ciphertext []byte) ([]byte, error) {
	msg, err := r.trySavedKeys(ciphertext)
	if err != nil || msg != nil {
		return msg, err
	}

	sealedHeader := ciphertext[:sealedHeaderSize]
	sealedMessage := ciphertext[sealedHeaderSize:]
	var nonce [nonceSize]byte
	copy(nonce[:], sealedHeader)
	sealedHeader = sealedHeader[len(nonce):]

	header, ok := secretbox.Open(nil, sealedHeader, &nonce, r.recvHeaderKey.ByteArray32())
	ok = ok && !isZeroKey(r.recvHeaderKey.ByteArray32())

	if ok {
		if len(header) != headerSize {
			return nil, errors.New("Ratchet: incorrect header size")
		}

		messageNum := binary.LittleEndian.Uint32(header[:4])
		provisionalChainKey, messageKey, savedKeys, err := r.saveKeys(r.recvHeaderKey.ByteArray32(), r.recvChainKey.ByteArray32(), messageNum, r.recvCount)
		if err != nil {
			return nil, err
		}

		copy(nonce[:], header[nonceInHeaderOffset:])
		msg, ok := secretbox.Open(nil, sealedMessage, &nonce, messageKey.ByteArray32())
		if !ok {
			return nil, errors.New("ratchet: corrupt message")
		}

		r.recvChainKey.Melt()
		defer r.recvChainKey.Freeze()
		r.recvChainKey.Copy(provisionalChainKey.ByteArray32()[:])

		r.mergeSavedKeys(savedKeys)
		r.recvCount = messageNum + 1
		return msg, nil
	}

	header, ok = secretbox.Open(nil, sealedHeader, &nonce, r.nextRecvHeaderKey.ByteArray32())
	if !ok {
		return nil, errors.New("Ratchet: cannot decrypt")
	}
	if len(header) != headerSize {
		return nil, errors.New("Ratchet: incorrect header size")
	}

	if r.ratchet {
		return nil, errors.New("Ratchet: received message encrypted to next header key without ratchet flag set")
	}

	messageNum := binary.LittleEndian.Uint32(header[:4])
	prevMessageCount := binary.LittleEndian.Uint32(header[4:8])

	_, _, oldSavedKeys, err := r.saveKeys(r.recvHeaderKey.ByteArray32(), r.recvChainKey.ByteArray32(), prevMessageCount, r.recvCount)
	if err != nil {
		return nil, err
	}

	var dhPublic, sharedKey, keyMaterial [32]byte
	copy(dhPublic[:], header[8:])

	curve25519.ScalarMult(&sharedKey, r.sendRatchetPrivate.ByteArray32(), &dhPublic)

	sha := sha3.New256()
	sha.Write(rootKeyUpdateLabel)
	sha.Write(r.rootKey.ByteArray32()[:])
	sha.Write(sharedKey[:])

	var rootKeyHMAC hash.Hash
	var chainKey *memguard.LockedBuffer

	sha.Sum(keyMaterial[:0])
	rootKeyHMAC = hmac.New(sha3.New256, keyMaterial[:])
	r.rootKey = deriveKey(rootKeyLabel, rootKeyHMAC)
	chainKey = deriveKey(chainKeyLabel, rootKeyHMAC)

	provisionalChainKey, messageKey, savedKeys, err := r.saveKeys(r.nextRecvHeaderKey.ByteArray32(), chainKey.ByteArray32(), messageNum, 0)
	if err != nil {
		return nil, err
	}

	copy(nonce[:], header[nonceInHeaderOffset:])
	msg, ok = secretbox.Open(nil, sealedMessage, &nonce, messageKey.ByteArray32())
	if !ok {
		return nil, errors.New("ratchet: corrupt message")
	}

	r.recvChainKey.Melt()
	defer r.recvChainKey.Freeze()
	r.recvHeaderKey.Melt()
	defer r.recvHeaderKey.Freeze()
	r.recvChainKey.Copy(provisionalChainKey.ByteArray32()[:])
	r.recvHeaderKey.Copy(r.nextRecvHeaderKey.ByteArray32()[:])

	r.nextRecvHeaderKey = deriveKey(headerKeyLabel, rootKeyHMAC)

	r.sendRatchetPrivate.Melt()
	defer r.sendRatchetPrivate.Freeze()
	r.sendRatchetPrivate.Wipe()

	r.recvRatchetPublic.Melt()
	defer r.recvRatchetPublic.Freeze()
	r.recvRatchetPublic.Copy(dhPublic[:])

	r.recvCount = messageNum + 1
	r.mergeSavedKeys(oldSavedKeys)
	r.mergeSavedKeys(savedKeys)
	r.ratchet = true

	return msg, nil
}

func dup(key *[32]byte) []byte {
	if key == nil {
		return nil
	}

	ret := make([]byte, 32)
	copy(ret, key[:])
	return ret
}

// MarshalBinary transforms the object into a stream
func (r *Ratchet) MarshalBinary() (data []byte, err error) {
	s := r.Marshal(time.Now(), RatchetKeyMaxLifetime)
	var serialized []byte
	enc := codec.NewEncoderBytes(&serialized, new(codec.CborHandle))
	if err := enc.Encode(s); err != nil {
		return nil, err
	}

	return serialized, nil
}

// Marshal transforms the object into a stream
func (r *Ratchet) Marshal(now time.Time, lifetime time.Duration) *State {
	s := &State{
		TheirSigningPublic:  dup(r.TheirSigningPublic.ByteArray32()),
		TheirIdentityPublic: dup(r.TheirIdentityPublic.ByteArray32()),
		MySigningPublic:     dup(r.MySigningPublic.ByteArray32()),
		MySigningPrivate:    r.MySigningPrivate.ByteArray64()[:],
		MyIdentityPrivate:   dup(r.MyIdentityPrivate.ByteArray32()),
		MyIdentityPublic:    dup(r.MyIdentityPublic.ByteArray32()),
		RootKey:             dup(r.rootKey.ByteArray32()),
		SendHeaderKey:       dup(r.sendHeaderKey.ByteArray32()),
		RecvHeaderKey:       dup(r.recvHeaderKey.ByteArray32()),
		NextSendHeaderKey:   dup(r.nextSendHeaderKey.ByteArray32()),
		NextRecvHeaderKey:   dup(r.nextRecvHeaderKey.ByteArray32()),
		SendChainKey:        dup(r.sendChainKey.ByteArray32()),
		RecvChainKey:        dup(r.recvChainKey.ByteArray32()),
		SendRatchetPrivate:  dup(r.sendRatchetPrivate.ByteArray32()),
		RecvRatchetPublic:   dup(r.recvRatchetPublic.ByteArray32()),
		SendCount:           r.sendCount,
		RecvCount:           r.recvCount,
		PrevSendCount:       r.prevSendCount,
		Private0:            dup(r.kxPrivate0.ByteArray32()),
		Private1:            dup(r.kxPrivate1.ByteArray32()),
		Ratchet:             r.ratchet,
	}

	for headerKey, messageKeys := range r.saved {
		keys := make([]*MessageKey, 0, len(messageKeys))
		for messageNum, savedKey := range messageKeys {
			if now.Sub(savedKey.timestamp) > lifetime {
				continue
			}
			keys = append(keys, &MessageKey{
				Num:          messageNum,
				Key:          dup(&savedKey.key),
				CreationTime: savedKey.timestamp.Unix(),
			})
		}
		s.SavedKeys = append(s.SavedKeys, &SavedKeys{
			HeaderKey:   dup(&headerKey),
			MessageKeys: keys,
		})
	}

	return s
}

func unmarshalKey(dst *[keySize]byte, src []byte) bool {
	if len(src) != keySize {
		return false
	}
	copy(dst[:], src)
	return true
}

var errSerialisedKeyLength = errors.New("ratchet: bad serialised key length")

// UnmarshalBinary transforms the stream into the object
func (r *Ratchet) UnmarshalBinary(data []byte) error {
	state := State{}
	err := codec.NewDecoderBytes(data, cborHandle).Decode(&state)
	if err != nil {
		return err
	}
	return r.Unmarshal(&state)
}

// Unmarshal transforms the stream into the object
func (r *Ratchet) Unmarshal(s *State) error {
	r.MySigningPublic.Melt()
	r.MySigningPrivate.Melt()

	r.MySigningPublic.Copy(s.MySigningPublic)
	r.MySigningPrivate.Copy(s.MySigningPrivate)

	defer r.MySigningPublic.Freeze()
	defer r.MySigningPrivate.Freeze()

	var tmp [keySize]byte
	if !unmarshalKey(&tmp, s.RootKey) {
		return errSerialisedKeyLength
	}

	var tmpA, tmpB, tmpC, tmpD [publicKeySize]byte
	if !unmarshalKey(&tmpA, s.TheirSigningPublic) ||
		!unmarshalKey(&tmpB, s.TheirIdentityPublic) ||
		!unmarshalKey(&tmpC, s.MyIdentityPrivate) ||
		!unmarshalKey(&tmpD, s.MyIdentityPublic) {
		return errSerialisedKeyLength
	}

	var tmpE, tmpF, tmpG, tmpH, tmpI, tmpJ, tmpK, tmpL [keySize]byte
	if !unmarshalKey(&tmpE, s.SendHeaderKey) ||
		!unmarshalKey(&tmpF, s.RecvHeaderKey) ||
		!unmarshalKey(&tmpG, s.NextSendHeaderKey) ||
		!unmarshalKey(&tmpH, s.NextRecvHeaderKey) ||
		!unmarshalKey(&tmpI, s.SendChainKey) ||
		!unmarshalKey(&tmpJ, s.RecvChainKey) ||
		!unmarshalKey(&tmpK, s.SendRatchetPrivate) ||
		!unmarshalKey(&tmpL, s.RecvRatchetPublic) {
		return errSerialisedKeyLength

	}

	r.TheirSigningPublic = memguard.NewBufferFromBytes(tmpA[:])
	r.TheirIdentityPublic = memguard.NewBufferFromBytes(tmpB[:])
	r.MyIdentityPrivate = memguard.NewBufferFromBytes(tmpC[:])
	r.MyIdentityPublic = memguard.NewBufferFromBytes(tmpD[:])
	r.rootKey = memguard.NewBufferFromBytes(tmp[:])
	r.sendHeaderKey = memguard.NewBufferFromBytes(tmpE[:])
	r.recvHeaderKey = memguard.NewBufferFromBytes(tmpF[:])
	r.nextSendHeaderKey = memguard.NewBufferFromBytes(tmpG[:])
	r.nextRecvHeaderKey = memguard.NewBufferFromBytes(tmpH[:])
	r.sendChainKey = memguard.NewBufferFromBytes(tmpI[:])
	r.recvChainKey = memguard.NewBufferFromBytes(tmpJ[:])
	r.sendRatchetPrivate = memguard.NewBufferFromBytes(tmpK[:])
	r.recvRatchetPublic = memguard.NewBufferFromBytes(tmpL[:])

	r.sendCount = s.SendCount
	r.recvCount = s.RecvCount
	r.prevSendCount = s.PrevSendCount
	r.ratchet = s.Ratchet

	if len(s.Private0) > 0 {
		var tmpE, tmpF [publicKeySize]byte
		if !unmarshalKey(&tmpE, s.Private0) ||
			!unmarshalKey(&tmpF, s.Private1) {
			return errSerialisedKeyLength
		}
		r.kxPrivate0.Destroy()
		r.kxPrivate1.Destroy()
		r.kxPrivate0 = memguard.NewBufferFromBytes(tmpE[:])
		r.kxPrivate1 = memguard.NewBufferFromBytes(tmpF[:])
	} else {
		r.kxPrivate0.Melt()
		r.kxPrivate1.Melt()
		r.kxPrivate0.Wipe()
		r.kxPrivate1.Wipe()

		defer r.kxPrivate0.Freeze()
		defer r.kxPrivate1.Freeze()
	}

	for _, saved := range s.SavedKeys {
		var headerKey [keySize]byte
		if !unmarshalKey(&headerKey, saved.HeaderKey) {
			return errSerialisedKeyLength
		}

		messageKeys := make(map[uint32]savedKey)
		for _, messageKey := range saved.MessageKeys {
			var savedKey savedKey
			if !unmarshalKey(&savedKey.key, messageKey.Key) {
				return errSerialisedKeyLength
			}

			savedKey.timestamp = time.Unix(messageKey.CreationTime, 0)
			messageKeys[messageKey.Num] = savedKey
		}

		r.saved[headerKey] = messageKeys
	}

	return nil
}
