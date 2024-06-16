package ratchet

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	//ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/nike/hybrid"
	"github.com/katzenpost/hpqc/nike/schemes"
)

//var nikeScheme = ecdh.Scheme(rand.Reader)

var nikeScheme = hybrid.NOBS_CSIDH512X25519

func pairedRatchet(t *testing.T) (aRatchet, bRatchet *Ratchet) {
	var err error
	aRatchet, err = InitRatchet(rand.Reader, nikeScheme)
	require.NoError(t, err)

	bRatchet, err = InitRatchet(rand.Reader, nikeScheme)
	require.NoError(t, err)

	// create the key exchange blobs
	akx, err := aRatchet.CreateKeyExchange()
	require.NoError(t, err)
	bkx, err := bRatchet.CreateKeyExchange()
	require.NoError(t, err)

	// do the actual key exchange
	err = aRatchet.ProcessKeyExchange(bkx)
	require.NoError(t, err)
	err = bRatchet.ProcessKeyExchange(akx)
	require.NoError(t, err)

	return
}

// Message encapsulates message that is sent or received.
type Message struct {
	Plaintext []byte
	Timestamp time.Time
	Outbound  bool
	Sent      bool
	Delivered bool
}

func Test_DoSendMessageOverhead(t *testing.T) {
	a, b := pairedRatchet(t)

	msg := []byte("test message")

	outMessage := Message{
		Plaintext: msg,
		Timestamp: time.Now(),
		Outbound:  true,
	}
	serialized, err := cbor.Marshal(outMessage)
	require.NoError(t, err)

	encrypted, err := a.Encrypt(nil, serialized)
	require.NoError(t, err)

	result, err := b.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, serialized, result)

	delta := (len(encrypted) - len(serialized)) - a.scheme.PublicKeySize()
	require.Equal(t, delta, doubleRatchetOverheadSansPubKey)
	delta2 := (len(encrypted) - len(msg)) - a.scheme.PublicKeySize()
	delta3 := delta2 - delta

	t.Logf("delta2 %d", delta2)
	t.Logf("delta3 %d", delta3)

	DestroyRatchet(a)
	DestroyRatchet(b)
}

func Test_CiphertextOverhead(t *testing.T) {
	a, b := pairedRatchet(t)

	msg := []byte("test message")
	encrypted, err := a.Encrypt(nil, msg)
	require.NoError(t, err)

	delta := (len(encrypted) - len(msg)) - a.scheme.PublicKeySize()

	// doubleRatchetOverheadSansPubKey is the number of bytes the ratchet adds in ciphertext overhead without nike.PublicKeySize
	require.Equal(t, delta, doubleRatchetOverheadSansPubKey)

	result, err := b.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, msg, result)

	DestroyRatchet(a)
	DestroyRatchet(b)
}

func Test_KeyExchange(t *testing.T) {
	a, b := pairedRatchet(t)

	msg := []byte("test message")
	encrypted, err := a.Encrypt(nil, msg)
	require.NoError(t, err)

	result, err := b.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, msg, result)

	DestroyRatchet(a)
	DestroyRatchet(b)
}

func Test_RealKeyExchange(t *testing.T) {
	// create two new ratchets
	a, err := InitRatchet(rand.Reader, nikeScheme)
	require.NoError(t, err)
	b, err := InitRatchet(rand.Reader, nikeScheme)
	require.NoError(t, err)

	// create the key exchange blobs
	akx, err := a.CreateKeyExchange()
	require.NoError(t, err)
	bkx, err := b.CreateKeyExchange()
	require.NoError(t, err)

	// do the actual key exchange
	err = a.ProcessKeyExchange(bkx)
	require.NoError(t, err)
	err = b.ProcessKeyExchange(akx)
	require.NoError(t, err)

	// try to encrypt and decrypt a message
	msg := []byte("test message")
	encrypted, err := a.Encrypt(nil, msg)
	require.NoError(t, err)
	result, err := b.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, msg, result)

	msg2 := []byte(`This essay might seem to focus on the ethical weight of
each scientist’s personal, professional choices. But I am actually more concerned
about how we, as cryptographers and computer scientists, act in aggregate. Our
collective behavior embodies values—and the institutions we create do, too.`)
	encrypted, err = a.Encrypt(nil, msg2)
	require.NoError(t, err)
	result, err = b.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, msg2, result)

	_, err = b.CreateKeyExchange()
	require.Error(t, ErrHandshakeAlreadyComplete, err)
	err = a.ProcessKeyExchange(bkx)
	require.Error(t, ErrHandshakeAlreadyComplete, err)

	DestroyRatchet(a)
	DestroyRatchet(b)

	err = a.ProcessKeyExchange(bkx)
	require.Error(t, ErrHandshakeAlreadyComplete, err)
	_, err = b.CreateKeyExchange()
	require.Error(t, ErrHandshakeAlreadyComplete, err)
}

func Test_Serialization0(t *testing.T) {
	// create two new ratchets
	a, err := InitRatchet(rand.Reader, nikeScheme)
	require.NoError(t, err)
	_, err = a.Save()
	require.NoError(t, err)
}

func Test_Serialization1(t *testing.T) {
	a, b := pairedRatchet(t)

	// 1
	msg := []byte("test message number one is a short one")
	encrypted, err := a.Encrypt(nil, msg)
	require.NoError(t, err)
	result, err := b.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, msg, result)

	serialized, err := a.Save()
	require.NoError(t, err)

	r, err := NewRatchetFromBytes(rand.Reader, serialized, nikeScheme)
	require.NoError(t, err)

	// 2
	msg2 := []byte(`The word privacy, its meaning abstract and debated, its connotations often
negative, is not a winning word. Privacy is for medical records, toileting, and
sex — not for democracy or freedom. The word anonymity is even worse: modern
political parlance has painted this as nearly a flavor of terrorism. Security is
more winning a word and, in fact, I spoke of secure messaging instead of private
messaging or anonymous messaging because I think it better captures what I
want conveyed: that a communication whose endpoints are manifest is not at all
secure. A person needs to feel insecure if using such a channel.`)
	encrypted, err = r.Encrypt(nil, msg2)
	require.NoError(t, err)
	result, err = b.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, msg2, result)

	// 3
	msg3 := []byte(`But even the word security doesn’t support a good framing of our problem:
we should try to speak of thwarting mass surveillance more than enhancing
privacy, anonymity, or security. As discussed before, we know instinctively
that ubiquitous surveillance is incompatible with freedom, democracy, and
human rights. 189 This makes surveillance a thing against which one can fight.
The surveillance camera and data center make visual our emerging dystopia,
while privacy, anonymity, and security are so abstract as to nearly defy visual
representation.`)
	encrypted, err = r.Encrypt(nil, msg3)
	require.NoError(t, err)
	result, err = b.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, msg3, result)

	DestroyRatchet(a)
	DestroyRatchet(b)
	DestroyRatchet(r)
}

type scriptAction struct {
	// object is one of sendA, sendB or sendDelayed. The first two options
	// cause a message to be sent from one party to the other. The latter
	// causes a previously delayed message, identified by id, to be
	// delivered.
	object int
	// result is one of deliver, drop or delay. If delay, then the message
	// is stored using the value in id. This value can be repeated later
	// with a sendDelayed.
	result int
	id     int
}

const (
	sendA = iota
	sendB
	sendDelayed
	deliver
	drop
	delay
)

func reinitRatchet(t *testing.T, r *Ratchet) *Ratchet {
	state, err := r.Save()
	require.NoError(t, err)
	DestroyRatchet(r)

	newR, err := NewRatchetFromBytes(rand.Reader, state, nikeScheme)
	require.NoError(t, err)

	return newR
}

func testScript(t *testing.T, script []scriptAction) {
	type delayedMessage struct {
		msg       []byte
		encrypted []byte
		fromA     bool
	}

	delayedMessages := make(map[int]delayedMessage)
	a, b := pairedRatchet(t)

	for i, action := range script {
		switch action.object {
		case sendA, sendB:
			sender, receiver := a, b
			if action.object == sendB {
				sender, receiver = receiver, sender
			}

			var msg [20]byte
			_, err := rand.Reader.Read(msg[:])
			require.NoError(t, err)
			encrypted, err := sender.Encrypt(nil, msg[:])
			require.NoError(t, err)

			switch action.result {
			case deliver:
				result, err := receiver.Decrypt(encrypted)
				require.NoError(t, err, fmt.Sprintf("#%d: receiver returned error: %s", i, err))
				require.Equal(t, msg[:], result, fmt.Sprintf("#%d: bad message: got %x, not %x", i, result, msg[:]))
			case delay:
				_, ok := delayedMessages[action.id]
				require.False(t, ok, fmt.Sprintf("#%d: already have delayed message with id %d", i, action.id))
				delayedMessages[action.id] = delayedMessage{msg[:], encrypted, sender == a}
			case drop:
			}
		case sendDelayed:
			delayed, ok := delayedMessages[action.id]
			require.True(t, ok, fmt.Sprintf("#%d: no such delayed message id: %d", i, action.id))

			receiver := a
			if delayed.fromA {
				receiver = b
			}

			result, err := receiver.Decrypt(delayed.encrypted)
			require.NoError(t, err, fmt.Sprintf("#%d: receiver returned error: %s", i, err))
			require.Equal(t, delayed.msg, result, fmt.Sprintf("#%d: bad message: got %x, not %x", i, result, delayed.msg))
		}

		a = reinitRatchet(t, a)
		b = reinitRatchet(t, b)
	}
}

func Test_RatchetBackAndForth(t *testing.T) {
	testScript(t, []scriptAction{
		{sendA, deliver, -1},
		{sendB, deliver, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
	})
}

func Test_RatchetReordering(t *testing.T) {
	script := []scriptAction{}
	script = append(script, scriptAction{sendA, deliver, -1})
	for i := 0; i < MaxMissingMessages; i++ {
		script = append(script, scriptAction{sendA, delay, i})
	}
	for i := MaxMissingMessages; i >= 0; i-- {
		script = append(script, scriptAction{sendA, deliver, i})
	}

	testScript(t, script)
}

func Test_RatchetReorderAfterDHRatchet(t *testing.T) {
	testScript(t, []scriptAction{
		{sendA, deliver, -1},
		{sendA, delay, 0},
		{sendB, deliver, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
		{sendDelayed, deliver, 0},
	})
}

func Test_RatchetDroppedMessages(t *testing.T) {
	testScript(t, []scriptAction{
		{sendA, drop, -1},
		{sendA, drop, -1},
		{sendA, drop, -1},
		{sendA, drop, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
	})
}

func Test_serialize_savedkeys(t *testing.T) {
	a, b := pairedRatchet(t)
	msg := []byte("test message")
	encrypted1, err := a.Encrypt(nil, msg)
	require.NoError(t, err)
	encrypted2, err := a.Encrypt(nil, msg)
	require.NoError(t, err)
	encrypted3, err := a.Encrypt(nil, msg)
	require.NoError(t, err)
	result, err := b.Decrypt(encrypted2)
	require.NoError(t, err)
	require.Equal(t, msg, result)

	serialized, err := a.Save()
	require.NoError(t, err)
	serialized2, err := b.Save()
	require.NoError(t, err)

	_, err = NewRatchetFromBytes(rand.Reader, serialized, nikeScheme)
	require.NoError(t, err)

	l, err := NewRatchetFromBytes(rand.Reader, serialized2, nikeScheme)
	require.NoError(t, err)

	result, err = l.Decrypt(encrypted3)
	require.NoError(t, err)
	require.Equal(t, msg, result)
	result, err = l.Decrypt(encrypted1)
	require.NoError(t, err)
	require.Equal(t, msg, result)
}

func Test_RatchetDuplicateMessage(t *testing.T) {
	a, b := pairedRatchet(t)
	msg1 := []byte("test message 1")
	msg2 := []byte("test message 2")
	msg3 := []byte("test message 3")
	encrypted1, err := a.Encrypt(nil, msg1)
	require.NoError(t, err)
	encrypted2, err := a.Encrypt(nil, msg2)
	require.NoError(t, err)
	encrypted3, err := a.Encrypt(nil, msg3)
	require.NoError(t, err)
	result, err := b.Decrypt(encrypted2)
	require.NoError(t, err)
	require.Equal(t, msg2, result)
	result, err = b.Decrypt(encrypted2)
	require.Error(t, err)
	require.Equal(t, []byte(nil), result)
	require.Equal(t, err, ErrDuplicateOrDelayed)
	result, err = b.Decrypt(encrypted1)
	require.NoError(t, err)
	require.Equal(t, msg1, result)
	result, err = b.Decrypt(encrypted3)
	require.NoError(t, err)
	require.Equal(t, msg3, result)
}

func Test_savedKeysMarshaling(t *testing.T) {
	key := [32]byte{}
	rand.Reader.Read(key[:])
	m := &messageKey{
		Num:          123,
		Key:          make([]byte, 32),
		CreationTime: 123,
	}
	rand.Reader.Read(m.Key)
	s := &savedKeys{
		HeaderKey:   key[:],
		MessageKeys: []*messageKey{m},
	}

	b, err := s.MarshalBinary()
	require.NoError(t, err)
	require.NotNil(t, b)
	s2 := &savedKeys{}
	err = s2.UnmarshalBinary(b)
	require.NoError(t, err)
}

func Test_NewRatchetFromBytes(t *testing.T) {
	nikeScheme := schemes.ByName("NOBS_CSIDH-X25519")

	bad_ratchet_bytes_1, err := hex.DecodeString("b46953617665644b657973f667526f6f744b657958201bf12876a392f837968846562b51be826a15a436b989544ce113c4f97af524446d53656e644865616465724b6579582038d4b4120e1c594f173d82ad32839e1406f7c5f5456f672aab87754207d42e016d526563764865616465724b657958205767f637b7ae3e7085c009b57be49d95e009f8226f5016e2d7ea81322d03a9c5714e65787453656e644865616465724b657958201b2f58818f9f59b4ce18cc0aa903e07b5d0cd36721a412b9dc0a7f385b99f5c4714e657874526563764865616465724b6579582038d4b4120e1c594f173d82ad32839e1406f7c5f5456f672aab87754207d42e016c53656e64436861696e4b65795820df5fe0e1690a2bcbc6f25ed98977df56d2d15a9681b60d858c3cb8ddccf871136c52656376436861696e4b657958205f19507964eec302763e1fdf6b12d4f8529b4c3be849c454fc50429773bf58d07253656e645261746368657450726976617465582099a6c6d2802cc763ce9120d00e8f0d356c0c3cf23ee93b708d2f7d06eb33c64f7152656376526174636865745075626c69635820b093cf98b3924da00bf277fbb296538dd8495bc033a83b6ff47ae3833b1a63327453656e645051526174636865745072697661746558253540e1b14f30f32dc4ef404eb40cff3e3cd1cb40fe35cd55542222b5c420efe245024cd40473526563765051526174636865745075626c69635840566ba49e64f066c4f4abdea91ac98c44b14a90fce9ad15595337442de6a438cec934a7343829784c0bf6031cd2c468c7b17142d00b1fd16b7f53f9b9bfb6540f6953656e64436f756e74026952656376436f756e74016d5072657653656e64436f756e7400685072697661746530f6685072697661746531f66a505150726976617465305825b25200d4254b5252ec214bc2ebe1c1c1ce2ee415212ec4c2cb0f201f013df22f1331d0f3346a505150726976617465315825543fbb3be43f2f03d3df4dcecc4e3b2c4125e2510df52eced05cbd52122c033c30f251dee06752617463686574f4")
	require.NoError(t, err)

	bad_ratchet_bytes_2, err := hex.DecodeString("b46953617665644b657973f667526f6f744b65795820515e30c19b63d93cb9126facbf5bb7f78835ca4b5864ddf5cd187be3001e1e426d53656e644865616465724b65795820f2f75b13d096bbc2bbc3a143a00502bfed75507bb17e7f19462397bb5de0b2d76d526563764865616465724b657958200000000000000000000000000000000000000000000000000000000000000000714e65787453656e644865616465724b65795820b4da80d25155b5605e395905cb9b223a82b3bcc39af244f6c9ccb87782853ec8714e657874526563764865616465724b65795820b4da80d25155b5605e395905cb9b223a82b3bcc39af244f6c9ccb87782853ec86c53656e64436861696e4b657958200c260d5b4a2244851644e43f744d47ddea444e4190406d5704eb974e3d75a5506c52656376436861696e4b6579582000000000000000000000000000000000000000000000000000000000000000007253656e6452617463686574507269766174655820a973bfc4874df442f72ad3f14a3c0bb8fb885af0691f2bafe78cca255495a6327152656376526174636865745075626c6963582000000000000000000000000000000000000000000000000000000000000000007453656e6450515261746368657450726976617465582504f10244b23d2eeb4cc2c4c2b1b14ed3b044e45cecf25102dc3252d11c5eddc320ff30c55f73526563765051526174636865745075626c69635840000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006953656e64436f756e74016952656376436f756e74006d5072657653656e64436f756e7400685072697661746530f6685072697661746531f66a505150726976617465305825ffc22e0b0fe3d0ede3d5b3222fd2c4dbfb520de2402be3c2d3b13b04b330bc33bb21b1edf26a50515072697661746531582504f10244b23d2eeb4cc2c4c2b1b14ed3b044e45cecf25102dc3252d11c5eddc320ff30c55f6752617463686574f4")
	require.NoError(t, err)
	r, err := NewRatchetFromBytes(rand.Reader, bad_ratchet_bytes_2, nikeScheme)
	require.NoError(t, err)
	r, err = NewRatchetFromBytes(rand.Reader, bad_ratchet_bytes_1, nikeScheme)
	require.NoError(t, err)

	_, err = r.CreateKeyExchange()
	require.NoError(t, err)
}
