package ratchet

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

func nowFunc() time.Time {
	var t time.Time
	return t
}

func pairedRatchet() (a, b *Ratchet) {
	var privA, pubA, privB, pubB [32]byte
	io.ReadFull(rand.Reader, privA[:])
	io.ReadFull(rand.Reader, privB[:])
	curve25519.ScalarBaseMult(&pubA, &privA)
	curve25519.ScalarBaseMult(&pubB, &privB)

	// These are the "Ed25519" public keys for the two parties. Of course,
	// they're not actually valid Ed25519 keys but that doesn't matter
	// here.
	var aSigningPublic, bSigningPublic [32]byte
	io.ReadFull(rand.Reader, aSigningPublic[:])
	io.ReadFull(rand.Reader, bSigningPublic[:])

	a, err := New(rand.Reader)
	if err != nil {
		panic(err)
	}
	b, err = New(rand.Reader)
	if err != nil {
		panic(err)
	}
	a.Now = nowFunc
	b.Now = nowFunc

	a.MyIdentityPrivate = privA
	a.MySigningPublic = aSigningPublic
	a.TheirIdentityPublic = pubB
	a.TheirSigningPublic = bSigningPublic

	b.MyIdentityPrivate = privB
	b.MySigningPublic = bSigningPublic
	b.TheirIdentityPublic = pubA
	b.TheirSigningPublic = aSigningPublic

	kxA, kxB := new(KeyExchange), new(KeyExchange)
	if err := a.FillKeyExchange(kxA); err != nil {
		panic(err)
	}
	if err := b.FillKeyExchange(kxB); err != nil {
		panic(err)
	}
	if err := a.CompleteKeyExchange(kxB); err != nil {
		panic(err)
	}
	if err := b.CompleteKeyExchange(kxA); err != nil {
		panic(err)
	}

	return
}

func TestExchange(t *testing.T) {
	a, b := pairedRatchet()

	msg := []byte("test message")
	encrypted := a.Encrypt(nil, msg)
	result, err := b.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, result) {
		t.Fatalf("result doesn't match: %x vs %x", msg, result)
	}
}

func TestActualRealExchange(t *testing.T) {
	// create two new ratchets
	a, err := New(rand.Reader)
	if err != nil {
		panic(err)
	}
	b, err := New(rand.Reader)
	if err != nil {
		panic(err)
	}

	// create the key exchange blobs
	akx, err := a.CreateKeyExchange()
	if err != nil {
		panic(err)
	}
	bkx, err := b.CreateKeyExchange()
	if err != nil {
		panic(err)
	}

	// do the actual key exchange
	err = a.DoKeyExchange(bkx)
	if err != nil {
		panic(err)
	}
	err = b.DoKeyExchange(akx)
	if err != nil {
		panic(err)
	}

	// try to encrypt and decrypt a message
	msg := []byte("test message")
	encrypted := a.Encrypt(nil, msg)
	result, err := b.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, result) {
		t.Fatalf("result doesn't match: %x vs %x", msg, result)
	}

	msg2 := []byte(`This essay might seem to focus on the ethical weight of
each scientist’s personal, professional choices. But I am actually more concerned
about how we, as cryptographers and computer scientists, act in aggregate. Our
collective behavior embodies values—and the institutions we create do, too.`)
	encrypted2 := a.Encrypt(nil, msg2)
	result2, err := b.Decrypt(encrypted2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg2, result2) {
		t.Fatalf("result doesn't match: %x vs %x", msg2, result2)
	}
}

func TestSerialization(t *testing.T) {
	a, b := pairedRatchet()

	// 1
	msg1 := []byte("test message number one is a short one")
	encrypted1 := a.Encrypt(nil, msg1)
	result1, err := b.Decrypt(encrypted1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg1, result1) {
		t.Fatalf("result doesn't match: %x vs %x", msg1, result1)
	}

	serialized, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c.UnmarshalBinary(serialized)

	// 2
	msg2 := []byte(`The word privacy, its meaning abstract and debated, its connotations often
negative, is not a winning word. Privacy is for medical records, toileting, and
sex — not for democracy or freedom. The word anonymity is even worse: modern
political parlance has painted this as nearly a flavor of terrorism. Security is
more winning a word and, in fact, I spoke of secure messaging instead of private
messaging or anonymous messaging because I think it better captures what I
want conveyed: that a communication whose endpoints are manifest is not at all
secure. A person needs to feel insecure if using such a channel.`)
	encrypted2 := c.Encrypt(nil, msg2)
	result2, err := b.Decrypt(encrypted2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg2, result2) {
		t.Fatalf("result doesn't match: %x vs %x", msg2, result2)
	}

	// 3
	msg3 := []byte(`But even the word security doesn’t support a good framing of our problem:
we should try to speak of thwarting mass surveillance more than enhancing
privacy, anonymity, or security. As discussed before, we know instinctively
that ubiquitous surveillance is incompatible with freedom, democracy, and
human rights. 189 This makes surveillance a thing against which one can fight.
The surveillance camera and data center make visual our emerging dystopia,
while privacy, anonymity, and security are so abstract as to nearly defy visual
representation.`)
	encrypted3 := c.Encrypt(nil, msg3)
	result3, err := b.Decrypt(encrypted3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg3, result3) {
		t.Fatalf("result doesn't match: %x vs %x", msg3, result3)
	}

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
	state := r.Marshal(nowFunc(), 1*time.Hour)
	newR, err := New(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newR.Now = nowFunc
	newR.MyIdentityPrivate = r.MyIdentityPrivate
	newR.TheirIdentityPublic = r.TheirIdentityPublic
	newR.MySigningPublic = r.MySigningPublic
	newR.TheirSigningPublic = r.TheirSigningPublic
	if err := newR.Unmarshal(state); err != nil {
		t.Fatalf("Failed to unmarshal: %s", err)
	}

	return newR

}

func testScript(t *testing.T, script []scriptAction) {
	type delayedMessage struct {
		msg       []byte
		encrypted []byte
		fromA     bool
	}
	delayedMessages := make(map[int]delayedMessage)
	a, b := pairedRatchet()

	for i, action := range script {
		switch action.object {
		case sendA, sendB:
			sender, receiver := a, b
			if action.object == sendB {
				sender, receiver = receiver, sender
			}

			var msg [20]byte
			rand.Reader.Read(msg[:])
			encrypted := sender.Encrypt(nil, msg[:])

			switch action.result {
			case deliver:
				result, err := receiver.Decrypt(encrypted)
				if err != nil {
					t.Fatalf("#%d: receiver returned error: %s", i, err)
				}
				if !bytes.Equal(result, msg[:]) {
					t.Fatalf("#%d: bad message: got %x, not %x", i, result, msg[:])
				}
			case delay:
				if _, ok := delayedMessages[action.id]; ok {
					t.Fatalf("#%d: already have delayed message with id %d", i, action.id)
				}
				delayedMessages[action.id] = delayedMessage{msg[:], encrypted, sender == a}
			case drop:
			}
		case sendDelayed:
			delayed, ok := delayedMessages[action.id]
			if !ok {
				t.Fatalf("#%d: no such delayed message id: %d", i, action.id)
			}

			receiver := a
			if delayed.fromA {
				receiver = b
			}

			result, err := receiver.Decrypt(delayed.encrypted)
			if err != nil {
				t.Fatalf("#%d: receiver returned error: %s", i, err)
			}
			if !bytes.Equal(result, delayed.msg) {
				t.Fatalf("#%d: bad message: got %x, not %x", i, result, delayed.msg)
			}
		}

		a = reinitRatchet(t, a)
		b = reinitRatchet(t, b)
	}
}

func TestBackAndForth(t *testing.T) {
	testScript(t, []scriptAction{
		{sendA, deliver, -1},
		{sendB, deliver, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
	})
}

func TestReorder(t *testing.T) {
	testScript(t, []scriptAction{
		{sendA, deliver, -1},
		{sendA, delay, 0},
		{sendA, deliver, -1},
		{sendDelayed, deliver, 0},
	})
}

func TestReorderAfterRatchet(t *testing.T) {
	testScript(t, []scriptAction{
		{sendA, deliver, -1},
		{sendA, delay, 0},
		{sendB, deliver, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
		{sendDelayed, deliver, 0},
	})
}

func TestDrop(t *testing.T) {
	testScript(t, []scriptAction{
		{sendA, drop, -1},
		{sendA, drop, -1},
		{sendA, drop, -1},
		{sendA, drop, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
	})
}
