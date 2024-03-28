package catshadow

import (
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
)

func TestQueue(t *testing.T) {
	assert := assert.New(t)
	q := new(Queue)

	providerHash1 := [32]byte{}
	_, err := rand.Read(providerHash1[:])
	assert.NoError(err)

	b := &queuedSpoolCommand{Provider: &providerHash1}
	err = q.Push(b)
	assert.NoError(err)
	s, err := q.Pop()
	assert.NoError(err)
	assert.Equal(b, s)

	providerHash2 := [32]byte{}
	_, err = rand.Read(providerHash2[:])
	assert.NoError(err)

	b = &queuedSpoolCommand{Provider: &providerHash2}

	err = q.Push(b)
	assert.NoError(err)

	serialized, err := cbor.Marshal(q)
	assert.NoError(err)
	assert.NotNil(serialized)

	newq := new(Queue)
	err = cbor.Unmarshal(serialized, &newq)
	assert.NoError(err)
	s, err = newq.Pop()
	assert.NoError(err)
	assert.Equal(b, s)

	sent := make([]*queuedSpoolCommand, 0)
	for i := 0; i < MaxQueueSize; i++ {
		myProviderHash := [32]byte{}
		_, err = rand.Read(providerHash2[:])
		assert.NoError(err)

		b = &queuedSpoolCommand{Provider: &myProviderHash}
		sent = append(sent, b)
		err := newq.Push(b)
		assert.NoError(err)
	}
	err = newq.Push(b)
	assert.Error(err)

	newq2 := new(Queue)
	serialized, err = cbor.Marshal(newq)
	assert.NoError(err)
	err = cbor.Unmarshal(serialized, &newq2)
	assert.NoError(err)
	for i := 0; i < MaxQueueSize; i++ {
		s, err = newq2.Pop()
		assert.NoError(err)
		assert.Equal(sent[i], s)
	}
	s, err = newq2.Pop()
	assert.Error(err)
}
