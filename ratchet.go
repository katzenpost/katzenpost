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

	"crypto/ed25519"
	"github.com/awnumar/memguard"
	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/core/crypto/extra25519"
	"github.com/katzenpost/core/utils"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/sha3"
)

const ()

var (
	ErrDuplicateOrDelayed                     = errors.New("Ratchet: duplicate message or message delayed longer than tolerance")
	ErrHandshakeAlreadyComplete               = errors.New("Ratchet: handshake already complete")
	ErrCannotDecrypt                          = errors.New("Ratchet: cannot decrypt")
	ErrIncorrectHeaderSize                    = errors.New("Ratchet: incorrect header size")
	ErrSerialisedKeyLength                    = errors.New("Ratchet: bad serialised key length")
	ErrNextEncryptedMessageWithoutRatchetFlag = errors.New("Ratchet: received message encrypted to next header key without ratchet flag set")
	ErrOldFormKeyExchange                     = errors.New("Ratchet: peer using old-form key exchange")
	ErrCorruptMessage                         = errors.New("Ratchet: corrupt message")
	ErrMessageExceedsReorderingLimit          = errors.New("Ratchet: message exceeds reordering limit")
	ErrEchoedDHValues                         = errors.New("Ratchet: peer echoed our own DH values back")
	ErrInvalidSignatureLength                 = errors.New("Ratchet: invalid signature length")
	ErrRatchetHeaderTooSmall                  = errors.New("Ratchet: header too small to be valid")
	ErrInvalidKeyExchange                     = errors.New("Ratchet: peer's key exchange is invalid")
	ErrFailedToInitializeRatchet              = errors.New("Ratchet: failed to initialize")
	ErrInvalidPubkey                          = errors.New("Ratchet: invalid public key")
	ErrInvalidPublicIdentityKey               = errors.New("Ratchet: invalid public identity key")
	ErrInvalidSignature                       = errors.New("Ratchet: invalid signature")
	ErrKeyExchangeKeysNotIsomorphicallyEqual  = errors.New("Ratchet: key exchange and identity public keys must be isomorphically equal")
)

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
	Key          *memguard.LockedBuffer
	CreationTime int64
}

// SavedKeys is structure containing the saved keys from delayed messages
type SavedKeys struct {
	HeaderKey   *memguard.LockedBuffer
	MessageKeys []*MessageKey
}

// MarshalBinary implements encoding.BinaryUnmarshaler interface
func (s *SavedKeys) MarshalBinary() ([]byte, error) {
	type messageKey struct {
		Num          uint32
		Key          []byte
		CreationTime int64
	}
	type savedKeys struct {
		HeaderKey   []byte
		MessageKeys []*messageKey
	}
	tmp := &savedKeys{}
	if s.HeaderKey.IsAlive() {
		tmp.HeaderKey = s.HeaderKey.Bytes()
		for _, m := range s.MessageKeys {
			tmp.MessageKeys = append(tmp.MessageKeys, &messageKey{Num: m.Num, Key: m.Key.Bytes(), CreationTime: m.CreationTime})
		}
	}
	return cbor.Marshal(tmp)
}

// UnmarshalBinary instantiates memguard.LockedBuffer instances for each deserialized key
func (s *SavedKeys) UnmarshalBinary(data []byte) error {
	type messageKey struct {
		Num          uint32
		Key          []byte
		CreationTime int64
	}
	type savedKeys struct {
		HeaderKey   []byte
		MessageKeys []*messageKey
	}
	tmp := &savedKeys{}

	cbor.Unmarshal(data, &tmp)
	if len(tmp.HeaderKey) == keySize {
		s.HeaderKey = memguard.NewBufferFromBytes(tmp.HeaderKey)
		for _, m := range tmp.MessageKeys {
			if len(m.Key) == keySize {
				s.MessageKeys = append(s.MessageKeys, &MessageKey{Num: m.Num,
					Key: memguard.NewBufferFromBytes(m.Key), CreationTime: m.CreationTime})
			}
		}
	}
	return nil
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
	key       *memguard.LockedBuffer
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
	saved map[*memguard.LockedBuffer]map[uint32]savedKey

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
		saved: make(map[*memguard.LockedBuffer]map[uint32]savedKey),
	}

	var err error
	r.kxPrivate0, err = memguard.NewBufferFromReader(rand, privateKeySize)
	if err != nil {
		return nil, err
	}
	r.kxPrivate1, err = memguard.NewBufferFromReader(rand, privateKeySize)
	if err != nil {
		return nil, err
	}

	mySigningPublic, mySigningPrivate, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, ErrFailedToInitializeRatchet
	}

	r.MySigningPublic = memguard.NewBufferFromBytes(mySigningPublic[:])
	r.MySigningPrivate = memguard.NewBufferFromBytes(mySigningPrivate[:])

	// OK
	r.MyIdentityPrivate = memguard.NewBuffer(privateKeySize)
	r.MyIdentityPublic = memguard.NewBuffer(publicKeySize)
	extra25519.PrivateKeyToCurve25519(r.MyIdentityPrivate.ByteArray32(), r.MySigningPrivate.ByteArray64())
	curve25519.ScalarBaseMult(r.MyIdentityPublic.ByteArray32(), r.MyIdentityPrivate.ByteArray32())

	// sanity math assertion
	curve25519Public := memguard.NewBuffer(publicKeySize)
	extra25519.PublicKeyToCurve25519(curve25519Public.ByteArray32(), r.MySigningPublic.ByteArray32())

	if !r.MyIdentityPublic.EqualTo(curve25519Public.Bytes()) {
		panic("Failed: Incorrect Public/Private Keys")
	}

	// zero initialize key fields
	r.TheirSigningPublic = memguard.NewBuffer(publicKeySize)
	r.TheirIdentityPublic = memguard.NewBuffer(publicKeySize)
	r.rootKey = memguard.NewBuffer(privateKeySize)
	r.sendHeaderKey = memguard.NewBuffer(privateKeySize)
	r.recvHeaderKey = memguard.NewBuffer(privateKeySize)
	r.nextSendHeaderKey = memguard.NewBuffer(privateKeySize)
	r.nextRecvHeaderKey = memguard.NewBuffer(privateKeySize)
	r.sendChainKey = memguard.NewBuffer(privateKeySize)
	r.recvChainKey = memguard.NewBuffer(privateKeySize)
	r.sendRatchetPrivate = memguard.NewBuffer(privateKeySize)
	r.recvRatchetPublic = memguard.NewBuffer(privateKeySize)

	return r, nil
}

// CreateKeyExchange created and add the appropiate fields for the KeyExchange
func (r *Ratchet) CreateKeyExchange() (*SignedKeyExchange, error) {
	kx := &KeyExchange{
		PublicKey:      r.MySigningPublic.Bytes(),
		IdentityPublic: r.MyIdentityPublic.Bytes(),
	}

	err := r.FillKeyExchange(kx)
	if err != nil {
		return nil, err
	}

	serialized, err := cbor.Marshal(kx)
	if err != nil {
		return nil, err
	}

	sig := ed25519.Sign(ed25519.PrivateKey(r.MySigningPrivate.Bytes()), serialized)
	return &SignedKeyExchange{
		Signed:    serialized,
		Signature: sig[:],
	}, nil
}

// FillKeyExchange sets elements of kx with key exchange information from the
// ratchet.
func (r *Ratchet) FillKeyExchange(kx *KeyExchange) error {
	if r.kxPrivate0 == nil || r.kxPrivate1 == nil {
		return ErrHandshakeAlreadyComplete
	}

	public0 := memguard.NewBuffer(publicKeySize)
	public1 := memguard.NewBuffer(publicKeySize)
	curve25519.ScalarBaseMult(public0.ByteArray32(), r.kxPrivate0.ByteArray32())
	curve25519.ScalarBaseMult(public1.ByteArray32(), r.kxPrivate1.ByteArray32())
	kx.Dh = public0.Bytes()
	kx.Dh1 = public1.Bytes()

	return nil
}

// deriveKey takes an HMAC object and a label and calculates out = HMAC(k, label).
func deriveKey(key *memguard.LockedBuffer, label []byte, h hash.Hash) {
	// XXX: I'm not sure here...
	h.Reset()
	h.Write(label)
	if !key.IsMutable() {
		key.Melt()
		defer key.Freeze()
	}
	h.Sum(key.Bytes()[:0])
	if key.Size() != keySize {
		panic("Hash function too large")
	}
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
	if len(signedKeyExchange.Signature) != signatureSize {
		return ErrInvalidSignatureLength
	}

	kx := new(KeyExchange)
	err := cbor.Unmarshal(signedKeyExchange.Signed, &kx)
	if err != nil {
		return err
	}

	if len(kx.PublicKey) != publicKeySize {
		return ErrInvalidPubkey
	}

	if len(kx.IdentityPublic) != publicKeySize {
		return ErrInvalidPublicIdentityKey
	}
	if !ed25519.Verify(ed25519.PublicKey(kx.PublicKey), signedKeyExchange.Signed, signedKeyExchange.Signature) {
		return ErrInvalidSignature
	}
	if r.TheirSigningPublic == nil {
		r.TheirSigningPublic = memguard.NewBuffer(publicKeySize)
	}

	r.TheirSigningPublic.Melt()
	defer r.TheirSigningPublic.Freeze()
	r.TheirSigningPublic.Copy(kx.PublicKey)

	var ed25519Public, curve25519Public [publicKeySize]byte
	copy(ed25519Public[:], kx.PublicKey)
	extra25519.PublicKeyToCurve25519(&curve25519Public, &ed25519Public)
	if !bytes.Equal(curve25519Public[:], kx.IdentityPublic) {
		return ErrKeyExchangeKeysNotIsomorphicallyEqual
	}

	if r.TheirIdentityPublic == nil {
		r.TheirIdentityPublic = memguard.NewBuffer(publicKeySize)
	}

	r.TheirIdentityPublic.Melt()
	defer r.TheirIdentityPublic.Freeze()
	r.TheirIdentityPublic.Copy(kx.IdentityPublic)

	return r.CompleteKeyExchange(kx)
}

// CompleteKeyExchange takes a KeyExchange message from the other party and
// establishes the ratchet.
func (r *Ratchet) CompleteKeyExchange(kx *KeyExchange) error {
	if r.kxPrivate0 == nil {
		return ErrHandshakeAlreadyComplete
	}

	var public0 [publicKeySize]byte
	curve25519.ScalarBaseMult(&public0, r.kxPrivate0.ByteArray32())

	if len(kx.Dh) != len(public0) {
		return ErrInvalidKeyExchange
	}

	if len(kx.Dh1) != len(public0) {
		return ErrOldFormKeyExchange
	}

	var amAlice bool
	switch bytes.Compare(public0[:], kx.Dh) {
	case -1:
		amAlice = true
	case 1:
		amAlice = false
	case 0:
		return ErrEchoedDHValues
	}

	var theirDH [publicKeySize]byte
	copy(theirDH[:], kx.Dh)

	//XXX can we make this a LockedBuffer as well?
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
	deriveKey(r.rootKey, rootKeyLabel, h)
	utils.ExplicitBzero(keyMaterial)

	if amAlice {
		deriveKey(r.recvHeaderKey, headerKeyLabel, h)
		deriveKey(r.nextSendHeaderKey, nextHeaderKeyLabel, h)
		deriveKey(r.nextRecvHeaderKey, nextHeaderKeyLabel, h)
		deriveKey(r.recvChainKey, chainKeyLabel, h)
		r.recvRatchetPublic.Melt()
		defer r.recvRatchetPublic.Freeze()
		r.recvRatchetPublic.Copy(kx.Dh1)
	} else {
		deriveKey(r.sendHeaderKey, headerKeyLabel, h)
		deriveKey(r.nextRecvHeaderKey, nextHeaderKeyLabel, h)
		deriveKey(r.nextSendHeaderKey, nextHeaderKeyLabel, h)
		deriveKey(r.sendChainKey, chainKeyLabel, h)
		r.sendRatchetPrivate.Melt()
		defer r.sendRatchetPrivate.Melt()
		r.sendRatchetPrivate.Copy(r.kxPrivate1.Bytes())
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

		sharedKey := memguard.NewBuffer(sharedKeySize)
		keyMaterial := memguard.NewBuffer(sharedKeySize)
		curve25519.ScalarMult(sharedKey.ByteArray32(), r.sendRatchetPrivate.ByteArray32(), r.recvRatchetPublic.ByteArray32())

		sha := sha3.New256()
		sha.Write(rootKeyUpdateLabel)
		sha.Write(r.rootKey.Bytes())
		sha.Write(sharedKey.Bytes())
		sha.Sum(keyMaterial.Bytes()[:0])
		h := hmac.New(sha3.New256, keyMaterial.Bytes())

		deriveKey(r.rootKey, rootKeyLabel, h)
		deriveKey(r.nextSendHeaderKey, headerKeyLabel, h)
		deriveKey(r.sendChainKey, chainKeyLabel, h)
		r.prevSendCount, r.sendCount = r.sendCount, 0
		r.ratchet = false
	}

	h := hmac.New(sha3.New256, r.sendChainKey.Bytes())
	messageKey := memguard.NewBuffer(keySize)
	deriveKey(messageKey, messageKeyLabel, h)
	deriveKey(r.sendChainKey, chainKeyStepLabel, h)

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
		return nil, ErrRatchetHeaderTooSmall
	}

	sealedHeader := ciphertext[:sealedHeaderSize]
	var nonce [nonceSize]byte
	copy(nonce[:], sealedHeader)
	sealedHeader = sealedHeader[len(nonce):]

	for headerKey, messageKeys := range r.saved {
		header, ok := secretbox.Open(nil, sealedHeader, &nonce, headerKey.ByteArray32())
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
		msg, ok := secretbox.Open(nil, sealedMessage, &nonce, msgKey.key.ByteArray32())
		if !ok {
			return nil, ErrCorruptMessage
		}
		delete(messageKeys, msgNum)
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
func (r *Ratchet) saveKeys(headerKey, recvChainKey *memguard.LockedBuffer, messageNum, receivedCount uint32) (provisionalChainKey, messageKey *memguard.LockedBuffer, savedKeys map[*memguard.LockedBuffer]map[uint32]savedKey, err error) {
	if messageNum < receivedCount {
		// This is a message from the past, but we didn't have a saved
		// key for it, which means that it's a duplicate message or we
		// expired the save key.
		err = ErrDuplicateOrDelayed
		return
	}

	missingMessages := messageNum - receivedCount
	if missingMessages > MaxMissingMessages {
		err = ErrMessageExceedsReorderingLimit
		return
	}

	// messageKeys maps from message number to message key.
	var messageKeys map[uint32]savedKey
	var now time.Time
	if missingMessages > 0 {
		messageKeys = make(map[uint32]savedKey)
	}
	if r.Now == nil {
		now = time.Now()
	} else {
		now = r.Now()
	}

	provisionalChainKey = memguard.NewBuffer(keySize)
	provisionalChainKey.Copy(recvChainKey.Bytes())

	for n := receivedCount; n <= messageNum; n++ {
		h := hmac.New(sha3.New256, provisionalChainKey.Bytes())
		messageKey = memguard.NewBuffer(keySize)
		deriveKey(messageKey, messageKeyLabel, h)
		deriveKey(provisionalChainKey, chainKeyStepLabel, h)

		if n < messageNum {
			messageKeys[n] = savedKey{messageKey, now}
		}
	}

	if messageKeys != nil {
		savedKeys = make(map[*memguard.LockedBuffer]map[uint32]savedKey)
		hkey := memguard.NewBuffer(keySize)
		hkey.Copy(headerKey.Bytes())
		savedKeys[hkey] = messageKeys
	}

	return
}

// mergeSavedKeys takes a map of saved message keys from saveKeys and merges it
// into r.saved.
func (r *Ratchet) mergeSavedKeys(newKeys map[*memguard.LockedBuffer]map[uint32]savedKey) {
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

func (r *Ratchet) wipeSavedKeys() {
	for headerKey, keys := range r.saved {
		for _, savedKey := range keys {
			savedKey.key.Destroy()
		}
		delete(r.saved, headerKey)
		headerKey.Destroy()
	}
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
	ok = ok && !utils.CtIsZero(r.recvHeaderKey.Bytes())

	if ok {
		if len(header) != headerSize {
			return nil, ErrIncorrectHeaderSize
		}

		messageNum := binary.LittleEndian.Uint32(header[:4])
		provisionalChainKey, messageKey, savedKeys, err := r.saveKeys(r.recvHeaderKey, r.recvChainKey, messageNum, r.recvCount)
		if err != nil {
			return nil, err
		}

		copy(nonce[:], header[nonceInHeaderOffset:])
		msg, ok := secretbox.Open(nil, sealedMessage, &nonce, messageKey.ByteArray32())
		if !ok {
			return nil, ErrCorruptMessage
		}

		r.recvChainKey.Melt()
		defer r.recvChainKey.Freeze()
		r.recvChainKey.Copy(provisionalChainKey.Bytes())

		r.mergeSavedKeys(savedKeys)
		r.recvCount = messageNum + 1
		return msg, nil
	}

	header, ok = secretbox.Open(nil, sealedHeader, &nonce, r.nextRecvHeaderKey.ByteArray32())
	if !ok {
		return nil, ErrCannotDecrypt
	}
	if len(header) != headerSize {
		return nil, ErrIncorrectHeaderSize
	}

	if r.ratchet {
		return nil, ErrNextEncryptedMessageWithoutRatchetFlag
	}

	messageNum := binary.LittleEndian.Uint32(header[:4])
	prevMessageCount := binary.LittleEndian.Uint32(header[4:8])

	_, _, oldSavedKeys, err := r.saveKeys(r.recvHeaderKey, r.recvChainKey, prevMessageCount, r.recvCount)
	if err != nil {
		return nil, err
	}

	dhPublic := memguard.NewBuffer(keySize)
	sharedKey := memguard.NewBuffer(keySize)
	keyMaterial := memguard.NewBuffer(keySize)
	dhPublic.Copy(header[8:])

	curve25519.ScalarMult(sharedKey.ByteArray32(), r.sendRatchetPrivate.ByteArray32(), dhPublic.ByteArray32())

	sha := sha3.New256()
	sha.Write(rootKeyUpdateLabel)
	sha.Write(r.rootKey.Bytes())
	sha.Write(sharedKey.Bytes())

	var rootKeyHMAC hash.Hash
	chainKey := memguard.NewBuffer(keySize)

	sha.Sum(keyMaterial.Bytes()[:0])
	rootKeyHMAC = hmac.New(sha3.New256, keyMaterial.Bytes())
	deriveKey(r.rootKey, rootKeyLabel, rootKeyHMAC)
	deriveKey(chainKey, chainKeyLabel, rootKeyHMAC)

	provisionalChainKey, messageKey, savedKeys, err := r.saveKeys(r.nextRecvHeaderKey, chainKey, messageNum, 0)
	if err != nil {
		return nil, err
	}

	copy(nonce[:], header[nonceInHeaderOffset:])
	msg, ok = secretbox.Open(nil, sealedMessage, &nonce, messageKey.ByteArray32())
	if !ok {
		return nil, ErrCorruptMessage
	}

	r.recvChainKey.Melt()
	defer r.recvChainKey.Freeze()
	r.recvHeaderKey.Melt()
	defer r.recvHeaderKey.Freeze()
	r.recvChainKey.Copy(provisionalChainKey.Bytes())
	r.recvHeaderKey.Copy(r.nextRecvHeaderKey.Bytes())

	deriveKey(r.nextRecvHeaderKey, headerKeyLabel, rootKeyHMAC)

	r.sendRatchetPrivate.Melt()
	defer r.sendRatchetPrivate.Freeze()
	r.sendRatchetPrivate.Wipe()

	r.recvRatchetPublic.Melt()
	defer r.recvRatchetPublic.Freeze()
	r.recvRatchetPublic.Copy(dhPublic.Bytes())

	r.recvCount = messageNum + 1
	r.mergeSavedKeys(oldSavedKeys)
	r.mergeSavedKeys(savedKeys)
	r.ratchet = true

	return msg, nil
}

// MarshalBinary transforms the object into a stream
func (r *Ratchet) MarshalBinary() (data []byte, err error) {
	s := r.Marshal(time.Now(), RatchetKeyMaxLifetime)
	return cbor.Marshal(s)
}

// Marshal transforms the object into a stream
func (r *Ratchet) Marshal(now time.Time, lifetime time.Duration) *State {
	s := &State{
		TheirSigningPublic:  r.TheirSigningPublic.Bytes(),
		TheirIdentityPublic: r.TheirIdentityPublic.Bytes(),
		MySigningPublic:     r.MySigningPublic.Bytes(),
		MySigningPrivate:    r.MySigningPrivate.Bytes(),
		MyIdentityPrivate:   r.MyIdentityPrivate.Bytes(),
		MyIdentityPublic:    r.MyIdentityPublic.Bytes(),
		RootKey:             r.rootKey.Bytes(),
		SendHeaderKey:       r.sendHeaderKey.Bytes(),
		RecvHeaderKey:       r.recvHeaderKey.Bytes(),
		NextSendHeaderKey:   r.nextSendHeaderKey.Bytes(),
		NextRecvHeaderKey:   r.nextRecvHeaderKey.Bytes(),
		SendChainKey:        r.sendChainKey.Bytes(),
		RecvChainKey:        r.recvChainKey.Bytes(),
		SendRatchetPrivate:  r.sendRatchetPrivate.Bytes(),
		RecvRatchetPublic:   r.recvRatchetPublic.Bytes(),
		SendCount:           r.sendCount,
		RecvCount:           r.recvCount,
		PrevSendCount:       r.prevSendCount,
		Private0:            r.kxPrivate0.Bytes(),
		Private1:            r.kxPrivate1.Bytes(),
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
				Key:          savedKey.key,
				CreationTime: savedKey.timestamp.UnixNano(),
			})
		}
		s.SavedKeys = append(s.SavedKeys, &SavedKeys{
			HeaderKey:   headerKey,
			MessageKeys: keys,
		})
	}

	return s
}

// UnmarshalBinary transforms the stream into the object
func (r *Ratchet) UnmarshalBinary(data []byte) error {
	state := State{}
	if err := cbor.Unmarshal(data, &state); err != nil {
		return err
	}
	return r.Unmarshal(&state)
}

// Unmarshal transforms the stream into the object
func (r *Ratchet) Unmarshal(s *State) error {
	// Melt all the LockedBuffer fields
	r.TheirSigningPublic.Melt()
	r.TheirIdentityPublic.Melt()
	r.MySigningPublic.Melt()
	r.MySigningPrivate.Melt()
	r.MyIdentityPrivate.Melt()
	r.MyIdentityPublic.Melt()
	r.rootKey.Melt()
	r.sendHeaderKey.Melt()
	r.recvHeaderKey.Melt()
	r.nextSendHeaderKey.Melt()
	r.nextRecvHeaderKey.Melt()
	r.sendChainKey.Melt()
	r.recvChainKey.Melt()
	r.sendRatchetPrivate.Melt()
	r.recvRatchetPublic.Melt()
	r.kxPrivate0.Melt()
	r.kxPrivate1.Melt()

	defer r.TheirSigningPublic.Freeze()
	defer r.TheirIdentityPublic.Freeze()
	defer r.MySigningPublic.Freeze()
	defer r.MySigningPrivate.Freeze()
	defer r.MyIdentityPrivate.Freeze()
	defer r.MyIdentityPublic.Freeze()
	defer r.rootKey.Freeze()
	defer r.sendHeaderKey.Freeze()
	defer r.recvHeaderKey.Freeze()
	defer r.nextSendHeaderKey.Freeze()
	defer r.nextRecvHeaderKey.Freeze()
	defer r.sendChainKey.Freeze()
	defer r.recvChainKey.Freeze()
	defer r.sendRatchetPrivate.Freeze()
	defer r.recvRatchetPublic.Freeze()
	defer r.kxPrivate0.Freeze()
	defer r.kxPrivate1.Freeze()

	r.MySigningPublic.Copy(s.MySigningPublic)
	r.MySigningPrivate.Copy(s.MySigningPrivate)
	r.rootKey.Copy(s.RootKey)
	r.TheirSigningPublic.Copy(s.TheirSigningPublic)
	r.TheirIdentityPublic.Copy(s.TheirIdentityPublic)
	r.MyIdentityPrivate.Copy(s.MyIdentityPrivate)
	r.MyIdentityPublic.Copy(s.MyIdentityPublic)
	r.sendHeaderKey.Copy(s.SendHeaderKey)
	r.recvHeaderKey.Copy(s.RecvHeaderKey)
	r.nextSendHeaderKey.Copy(s.NextSendHeaderKey)
	r.nextRecvHeaderKey.Copy(s.NextRecvHeaderKey)
	r.sendChainKey.Copy(s.SendChainKey)
	r.recvChainKey.Copy(s.RecvChainKey)
	r.sendRatchetPrivate.Copy(s.SendRatchetPrivate)
	r.recvRatchetPublic.Copy(s.RecvRatchetPublic)

	r.sendCount = s.SendCount
	r.recvCount = s.RecvCount
	r.prevSendCount = s.PrevSendCount
	r.ratchet = s.Ratchet

	if len(s.Private0) > 0 {
		r.kxPrivate0.Copy(s.Private0)
		r.kxPrivate1.Copy(s.Private1)
	} else {
		r.kxPrivate0.Melt()
		r.kxPrivate1.Melt()
		r.kxPrivate0.Wipe()
		r.kxPrivate1.Wipe()

		defer r.kxPrivate0.Freeze()
		defer r.kxPrivate1.Freeze()
	}

	for _, saved := range s.SavedKeys {
		if saved.HeaderKey.Size() != keySize {
			return ErrSerialisedKeyLength
		}

		messageKeys := make(map[uint32]savedKey)
		for _, messageKey := range saved.MessageKeys {
			if messageKey.Key.Size() != keySize {
				return ErrSerialisedKeyLength
			}
			savedKey := savedKey{key: messageKey.Key}
			savedKey.timestamp = time.Unix(0, messageKey.CreationTime)
			messageKeys[messageKey.Num] = savedKey
		}

		r.saved[saved.HeaderKey] = messageKeys
	}

	return nil
}

// DestroyRatchet destroys the ratchet
func DestroyRatchet(r *Ratchet) {
	r.TheirSigningPublic.Destroy()
	r.TheirIdentityPublic.Destroy()
	r.MySigningPublic.Destroy()
	r.MySigningPrivate.Destroy()
	r.MyIdentityPrivate.Destroy()
	r.MyIdentityPublic.Destroy()

	r.rootKey.Destroy()
	r.sendHeaderKey.Destroy()
	r.recvHeaderKey.Destroy()
	r.nextSendHeaderKey.Destroy()
	r.nextRecvHeaderKey.Destroy()
	r.sendChainKey.Destroy()
	r.recvChainKey.Destroy()
	r.sendRatchetPrivate.Destroy()
	r.recvRatchetPublic.Destroy()
	r.sendCount, r.recvCount = uint32(0), uint32(0)
	r.prevSendCount = uint32(0)
	r.kxPrivate0.Destroy()
	r.kxPrivate1.Destroy()

	r.wipeSavedKeys()
}
