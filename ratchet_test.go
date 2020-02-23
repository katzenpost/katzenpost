package ratchet

import (
	"crypto/rand"
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type DoubleRatchetSuite struct{}

var _ = Suite(&DoubleRatchetSuite{})

// TODO: there are tests missing:
// what if both start sending at the same time

func now() time.Time {
	var t time.Time
	return t
}

func pairedRatchet(c *C) (a, b *Ratchet) {
	var privA, pubA, privB, pubB [publicKeySize]byte
	io.ReadFull(rand.Reader, privA[:])
	io.ReadFull(rand.Reader, privB[:])
	curve25519.ScalarBaseMult(&pubA, &privA)
	curve25519.ScalarBaseMult(&pubB, &privB)

	// These are the "Ed25519" public keys for the two parties. Of course,
	// they're not actually valid Ed25519 keys but that doesn't matter
	// here.
	// this seems to be the signed prekey
	var aSigningPublic, bSigningPublic [publicKeySize]byte
	io.ReadFull(rand.Reader, aSigningPublic[:])
	io.ReadFull(rand.Reader, bSigningPublic[:])

	a, err := NewRatchet(rand.Reader)
	c.Assert(err, IsNil)

	b, err = NewRatchet(rand.Reader)
	c.Assert(err, IsNil)

	a.Now = now
	b.Now = now

	// TODO: this is repeated
	a.MyIdentityPrivate = privA
	a.MySigningPublic = aSigningPublic
	a.TheirIdentityPublic = pubB
	a.TheirSigningPublic = bSigningPublic

	b.MyIdentityPrivate = privB
	b.MySigningPublic = bSigningPublic
	b.TheirIdentityPublic = pubA
	b.TheirSigningPublic = aSigningPublic

	kxA, kxB := new(KeyExchange), new(KeyExchange)

	err = a.FillKeyExchange(kxA)
	c.Assert(err, IsNil)

	err = b.FillKeyExchange(kxB)
	c.Assert(err, IsNil)

	err = a.CompleteKeyExchange(kxB)
	c.Assert(err, IsNil)

	err = b.CompleteKeyExchange(kxA)
	c.Assert(err, IsNil)

	return
}

func (s *DoubleRatchetSuite) Test_KeyExchange(c *C) {
	a, b := pairedRatchet(c)

	msg := []byte("test message")
	encrypted := a.Encrypt(nil, msg)
	result, err := b.Decrypt(encrypted)
	c.Assert(err, IsNil)

	c.Assert(msg, DeepEquals, result)
}

// TODO: how is this test different?
func (s *DoubleRatchetSuite) Test_RealKeyExchange(c *C) {
	// create two new ratchets
	a, err := NewRatchet(rand.Reader)
	if err != nil {
		panic(err)
	}
	b, err := NewRatchet(rand.Reader)
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
	err = a.ProcessKeyExchange(bkx)
	if err != nil {
		panic(err)
	}
	err = b.ProcessKeyExchange(akx)
	if err != nil {
		panic(err)
	}

	// try to encrypt and decrypt a message
	msg := []byte("test message")
	encrypted := a.Encrypt(nil, msg)
	result, err := b.Decrypt(encrypted)
	c.Assert(err, IsNil)

	c.Assert(msg, DeepEquals, result)

	msg2 := []byte(`This essay might seem to focus on the ethical weight of
each scientist’s personal, professional choices. But I am actually more concerned
about how we, as cryptographers and computer scientists, act in aggregate. Our
collective behavior embodies values—and the institutions we create do, too.`)
	encrypted = a.Encrypt(nil, msg2)
	result, err = b.Decrypt(encrypted)

	c.Assert(err, IsNil)
	c.Assert(msg2, DeepEquals, result)
}

func (s *DoubleRatchetSuite) Test_Serialization(c *C) {
	a, b := pairedRatchet(c)

	// 1
	msg := []byte("test message number one is a short one")
	encrypted := a.Encrypt(nil, msg)
	result, err := b.Decrypt(encrypted)
	c.Assert(err, IsNil)
	c.Assert(msg, DeepEquals, result)

	serialized, err := a.MarshalBinary()
	c.Assert(err, IsNil)

	r, err := NewRatchet(rand.Reader)
	c.Assert(err, IsNil)

	r.UnmarshalBinary(serialized)

	// 2
	msg2 := []byte(`The word privacy, its meaning abstract and debated, its connotations often
negative, is not a winning word. Privacy is for medical records, toileting, and
sex — not for democracy or freedom. The word anonymity is even worse: modern
political parlance has painted this as nearly a flavor of terrorism. Security is
more winning a word and, in fact, I spoke of secure messaging instead of private
messaging or anonymous messaging because I think it better captures what I
want conveyed: that a communication whose endpoints are manifest is not at all
secure. A person needs to feel insecure if using such a channel.`)
	encrypted = r.Encrypt(nil, msg2)
	result, err = b.Decrypt(encrypted)
	c.Assert(err, IsNil)
	c.Assert(msg2, DeepEquals, result)

	// 3
	msg3 := []byte(`But even the word security doesn’t support a good framing of our problem:
we should try to speak of thwarting mass surveillance more than enhancing
privacy, anonymity, or security. As discussed before, we know instinctively
that ubiquitous surveillance is incompatible with freedom, democracy, and
human rights. 189 This makes surveillance a thing against which one can fight.
The surveillance camera and data center make visual our emerging dystopia,
while privacy, anonymity, and security are so abstract as to nearly defy visual
representation.`)
	encrypted = r.Encrypt(nil, msg3)
	result, err = b.Decrypt(encrypted)
	c.Assert(err, IsNil)
	c.Assert(msg3, DeepEquals, result)
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

func reinitRatchet(c *C, r *Ratchet) *Ratchet {
	state := r.Marshal(now(), 1*time.Hour)
	newR, err := NewRatchet(rand.Reader)
	c.Assert(err, IsNil)

	newR.Now = now
	newR.MyIdentityPrivate = r.MyIdentityPrivate
	newR.TheirIdentityPublic = r.TheirIdentityPublic
	newR.MySigningPublic = r.MySigningPublic
	newR.TheirSigningPublic = r.TheirSigningPublic

	err = newR.Unmarshal(state)
	c.Assert(err, IsNil)

	return newR

}

func testScript(c *C, script []scriptAction) {
	type delayedMessage struct {
		msg       []byte
		encrypted []byte
		fromA     bool
	}

	delayedMessages := make(map[int]delayedMessage)
	a, b := pairedRatchet(c)

	for _, action := range script {
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
				c.Assert(err, IsNil)
				c.Assert(result, DeepEquals, msg[:])

			case delay:
				ok := delayedMessages[action.id]
				c.Assert(ok, Not(IsNil))

				delayedMessages[action.id] = delayedMessage{msg[:], encrypted, sender == a}
			case drop:
			}
		case sendDelayed:
			delayed, ok := delayedMessages[action.id]
			c.Assert(ok, Equals, true)

			receiver := a
			if delayed.fromA {
				receiver = b
			}

			result, err := receiver.Decrypt(delayed.encrypted)
			c.Assert(err, IsNil)
			c.Assert(result, DeepEquals, delayed.msg)
		}

		a = reinitRatchet(c, a)
		b = reinitRatchet(c, b)
	}
}

func (s *DoubleRatchetSuite) Test_RatchetBackAndForth(c *C) {
	testScript(c, []scriptAction{
		{sendA, deliver, -1},
		{sendB, deliver, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
	})
}

func (s *DoubleRatchetSuite) Test_RatchetReordering(c *C) {
	testScript(c, []scriptAction{
		{sendA, deliver, -1},
		{sendA, delay, 0},
		{sendA, deliver, -1},
		{sendDelayed, deliver, 0},
	})
}

func (s *DoubleRatchetSuite) Test_RatchetReorderAfterDHRatchet(c *C) {
	testScript(c, []scriptAction{
		{sendA, deliver, -1},
		{sendA, delay, 0},
		{sendB, deliver, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
		{sendDelayed, deliver, 0},
	})
}

func (s *DoubleRatchetSuite) Test_RatchetDroppedMessages(c *C) {
	testScript(c, []scriptAction{
		{sendA, drop, -1},
		{sendA, drop, -1},
		{sendA, drop, -1},
		{sendA, drop, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
	})
}
