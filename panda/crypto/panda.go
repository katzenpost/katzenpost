package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"github.com/golang/protobuf/proto"
	panda_proto "github.com/katzenpost/katzenpost/panda/crypto/proto"
	"github.com/katzenpost/katzenpost/panda/crypto/rijndael"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"
	"gopkg.in/op/go-logging.v1"
)

var ShutdownErrMessage = "panda: shutdown requested"

type MeetingPlace interface {
	Padding() int
	Exchange(id, message []byte, shutdown <-chan interface{}) ([]byte, error)
}

type PandaUpdate struct {
	ID         uint64
	Err        error
	Serialised []byte
	Result     []byte
}

type KeyExchange struct {
	sync.Mutex

	log          *logging.Logger
	shutdownChan <-chan interface{}

	pandaChan chan PandaUpdate
	contactID uint64

	rand         io.Reader
	status       panda_proto.KeyExchange_Status
	meetingPlace MeetingPlace
	sharedSecret []byte
	sharedRandom []byte
	serialised   []byte
	kxBytes      []byte

	key, meeting1, meeting2 [32]byte
	dhPublic, dhPrivate     [32]byte
	sharedKey               [32]byte
	message1, message2      []byte
}

func NewKeyExchange(rand io.Reader, log *logging.Logger, meetingPlace MeetingPlace, sharedRandom []byte, sharedSecret []byte, kxBytes []byte, contactID uint64, pandaChan chan PandaUpdate, shutdownChan <-chan interface{}) (*KeyExchange, error) {
	if 24 /* nonce */ +4 /* length */ +len(kxBytes)+secretbox.Overhead > meetingPlace.Padding() {
		return nil, errors.New("panda: key exchange too large for meeting place")
	}

	if len(sharedRandom) != 32 {
		return nil, errors.New("panda: SharedRandomValue is not 32 bytes long")
	}
	kx := &KeyExchange{
		rand:         rand,
		log:          log,
		meetingPlace: meetingPlace,
		status:       panda_proto.KeyExchange_INIT,
		sharedSecret: sharedSecret,
		sharedRandom: sharedRandom,
		kxBytes:      kxBytes,
		contactID:    contactID,
		pandaChan:    pandaChan,
		shutdownChan: shutdownChan,
	}

	if _, err := io.ReadFull(kx.rand, kx.dhPrivate[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&kx.dhPublic, &kx.dhPrivate)
	err := kx.updateSerialised()
	if err != nil {
		return nil, err
	}

	return kx, nil
}

func UnmarshalKeyExchange(rand io.Reader, log *logging.Logger, meetingPlace MeetingPlace, serialised []byte, contactID uint64, pandaChan chan PandaUpdate, shutdownChan <-chan interface{}) (*KeyExchange, error) {
	var p panda_proto.KeyExchange
	if err := proto.Unmarshal(serialised, &p); err != nil {
		return nil, err
	}

	kx := &KeyExchange{
		rand:         rand,
		log:          log,
		meetingPlace: meetingPlace,
		status:       p.GetStatus(),
		sharedSecret: p.SharedSecret,
		sharedRandom: p.SharedRandom,
		serialised:   serialised,
		kxBytes:      p.KeyExchangeBytes,
		message1:     p.Message1,
		message2:     p.Message2,
		contactID:    contactID,
		pandaChan:    pandaChan,
		shutdownChan: shutdownChan,
	}

	copy(kx.key[:], p.Key)
	copy(kx.meeting1[:], p.Meeting1)
	copy(kx.meeting2[:], p.Meeting2)
	copy(kx.sharedKey[:], p.SharedKey)
	copy(kx.dhPrivate[:], p.DhPrivate)
	curve25519.ScalarBaseMult(&kx.dhPublic, &kx.dhPrivate)

	return kx, nil
}

func (kx *KeyExchange) Marshal() []byte {
	kx.Lock()
	defer kx.Unlock()

	return kx.serialised
}

func (kx *KeyExchange) updateSerialised() error {
	p := &panda_proto.KeyExchange{
		Status:           kx.status.Enum(),
		SharedSecret:     kx.sharedSecret,
		SharedRandom:     kx.sharedRandom,
		KeyExchangeBytes: kx.kxBytes,
	}
	if kx.status != panda_proto.KeyExchange_INIT {
		p.DhPrivate = kx.dhPrivate[:]
		p.Key = kx.key[:]
		p.Meeting1 = kx.meeting1[:]
		p.Meeting2 = kx.meeting2[:]
		p.Message1 = kx.message1
		p.Message2 = kx.message2
		p.SharedKey = kx.sharedKey[:]
	}
	serialised, err := proto.Marshal(p)
	if err != nil {
		return err
	}

	kx.Lock()
	defer kx.Unlock()

	kx.serialised = serialised
	return nil
}

// SetSharedRandom updates the KeyExchange SharedRandom and resets the protocol state back to KeyExchange_INIT.
// The caller MUST halt an running KeyExchange before calling SetSharedRandom.
func (kx *KeyExchange) SetSharedRandom(srv []byte) {
	kx.Lock()
	defer kx.Unlock()

	if bytes.Equal(kx.sharedRandom, srv) {
		return
	}
	kx.sharedRandom = srv
	kx.status = panda_proto.KeyExchange_INIT
}

func (kx *KeyExchange) Run() {
	switch kx.status {
	case panda_proto.KeyExchange_INIT:
		if err := kx.derivePassword(); err != nil {
			kx.log.Error(err.Error())
			select {
			case <-kx.shutdownChan:
				kx.log.Error(ShutdownErrMessage)
			case kx.pandaChan <- PandaUpdate{ID: kx.contactID, Err: err}:
			}
			return
		}
		kx.status = panda_proto.KeyExchange_EXCHANGE1
		err := kx.updateSerialised()
		if err != nil {
			kx.log.Error(err.Error())
			select {
			case <-kx.shutdownChan:
				kx.log.Error(ShutdownErrMessage)
			case kx.pandaChan <- PandaUpdate{ID: kx.contactID, Err: err}:
			}
			return
		}
		kx.log.Info("password derivation complete.")
		select {
		case <-kx.shutdownChan:
			kx.log.Error(ShutdownErrMessage)
			return
		case kx.pandaChan <- PandaUpdate{ID: kx.contactID, Serialised: kx.Marshal()}:
		}
		fallthrough
	case panda_proto.KeyExchange_EXCHANGE1:
		if err := kx.exchange1(); err != nil {
			kx.log.Error(err.Error())
			select {
			case <-kx.shutdownChan:
				kx.log.Error(ShutdownErrMessage)
			case kx.pandaChan <- PandaUpdate{ID: kx.contactID, Err: err}:
			}
			return
		}
		kx.status = panda_proto.KeyExchange_EXCHANGE2
		err := kx.updateSerialised()
		if err != nil {
			kx.log.Error(err.Error())
			select {
			case <-kx.shutdownChan:
				kx.log.Error(ShutdownErrMessage)
			case kx.pandaChan <- PandaUpdate{ID: kx.contactID, Err: err}:
			}
			return
		}
		kx.log.Info("first message exchange complete")
		select {
		case <-kx.shutdownChan:
			kx.log.Error(ShutdownErrMessage)
			return
		case kx.pandaChan <- PandaUpdate{ID: kx.contactID, Serialised: kx.Marshal()}:
		}
		fallthrough
	case panda_proto.KeyExchange_EXCHANGE2:
		reply, err := kx.exchange2()
		select {
		case <-kx.shutdownChan:
			kx.log.Error(ShutdownErrMessage)
		case kx.pandaChan <- PandaUpdate{ID: kx.contactID, Err: err, Result: reply}:
		}
		return
	default:
		select {
		case <-kx.shutdownChan:
			kx.log.Error(ShutdownErrMessage)
			return

		case kx.pandaChan <- PandaUpdate{ID: kx.contactID, Err: errors.New("unknown state")}:
		}
		return
	}

	// unreachable
}

func (kx *KeyExchange) derivePassword() error {
	data := argon2.Key(kx.sharedSecret, kx.sharedRandom, 3, 32*1024, 4, 32*3)
	copy(kx.key[:], data)
	copy(kx.meeting1[:], data[32:])
	copy(kx.meeting2[:], data[64:])

	var encryptedDHPublic [32]byte
	rijndael.NewCipher(&kx.key).Encrypt(&encryptedDHPublic, &kx.dhPublic)

	l := len(encryptedDHPublic)
	if padding := kx.meetingPlace.Padding(); l > padding {
		return errors.New("panda: initial message too large for meeting place")
	} else if l < padding {
		l = padding
	}

	kx.message1 = make([]byte, l)
	copy(kx.message1, encryptedDHPublic[:])
	if _, err := io.ReadFull(kx.rand, kx.message1[len(encryptedDHPublic):]); err != nil {
		return err
	}

	return nil
}

func (kx *KeyExchange) exchange1() error {
	reply, err := kx.meetingPlace.Exchange(kx.meeting1[:], kx.message1[:], kx.shutdownChan)
	if err != nil {
		return err
	}

	var peerDHPublic, encryptedPeerDHPublic [32]byte
	if len(reply) < len(encryptedPeerDHPublic) {
		return errors.New("panda: meeting point reply too small")
	}

	copy(encryptedPeerDHPublic[:], reply)
	rijndael.NewCipher(&kx.key).Decrypt(&peerDHPublic, &encryptedPeerDHPublic)

	curve25519.ScalarMult(&kx.sharedKey, &kx.dhPrivate, &peerDHPublic)

	paddedLen := kx.meetingPlace.Padding()
	padded := make([]byte, paddedLen-24 /* nonce */ -secretbox.Overhead)
	binary.LittleEndian.PutUint32(padded, uint32(len(kx.kxBytes)))
	copy(padded[4:], kx.kxBytes)
	if _, err := io.ReadFull(kx.rand, padded[4+len(kx.kxBytes):]); err != nil {
		return err
	}

	var nonce [24]byte
	if _, err := io.ReadFull(kx.rand, nonce[:]); err != nil {
		return err
	}

	kx.message2 = make([]byte, paddedLen)
	copy(kx.message2, nonce[:])
	secretbox.Seal(kx.message2[24:24], padded, &nonce, &kx.sharedKey)

	return nil
}

func (kx *KeyExchange) exchange2() ([]byte, error) {
	reply, err := kx.meetingPlace.Exchange(kx.meeting2[:], kx.message2[:], kx.shutdownChan)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	if len(reply) < len(nonce) {
		return nil, errors.New("panda: meeting point reply too small")
	}

	if kx.sharedKey[0] == 0 && kx.sharedKey[1] == 0 {
		return nil, errors.New("exchange2 failure, shared keys are zero")
	}
	copy(nonce[:], reply)
	message, ok := secretbox.Open(nil, reply[24:], &nonce, &kx.sharedKey)
	if !ok {
		return nil, errors.New("panda: peer's message cannot be authenticated")
	}

	if len(message) < 4 {
		return nil, errors.New("panda: peer's message is invalid")
	}
	l := binary.LittleEndian.Uint32(message)
	message = message[4:]
	if l > uint32(len(message)) {
		return nil, errors.New("panda: peer's message is truncated")
	}
	message = message[:int(l)]
	return message, nil
}
