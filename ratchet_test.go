package ratchet

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func pairedRatchet(t *testing.T) (aRatchet, bRatchet *Ratchet) {
	var err error
	aRatchet, err = InitRatchet(rand.Reader)
	require.NoError(t, err)

	bRatchet, err = InitRatchet(rand.Reader)
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
	a, err := InitRatchet(rand.Reader)
	require.NoError(t, err)
	b, err := InitRatchet(rand.Reader)
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

	DestroyRatchet(a)
	DestroyRatchet(b)
}

func Test_Serialization0(t *testing.T) {
	// create two new ratchets
	a, err := InitRatchet(rand.Reader)
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

	r, err := NewRatchetFromBytes(rand.Reader, serialized)
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

	newR, err := NewRatchetFromBytes(rand.Reader, state)
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
			rand.Reader.Read(msg[:])
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

	_, err = NewRatchetFromBytes(rand.Reader, serialized)
	require.NoError(t, err)

	l, err := NewRatchetFromBytes(rand.Reader, serialized2)
	require.NoError(t, err)

	result, err = l.Decrypt(encrypted3)
	require.NoError(t, err)
	result, err = l.Decrypt(encrypted1)
	require.NoError(t, err)
}
