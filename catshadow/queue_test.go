package catshadow

import (
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestQueue(t *testing.T) {
	assert := assert.New(t)
	q := new(Queue)
	b := &queuedSpoolCommand{Provider: "foo"}
	err := q.Push(b)
	assert.NoError(err)
	s, err := q.Pop()
	assert.NoError(err)
	assert.Equal(b, s)

	b = &queuedSpoolCommand{Provider: "bar"}
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
		b = &queuedSpoolCommand{Provider: fmt.Sprintf("foo %d", i)}
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
	for _, x := range sent {
		x.Provider = "bar"
	}
	for i := 0; i < MaxQueueSize; i++ {
		s, err = newq2.Pop()
		assert.NoError(err)
		assert.NotEqual(sent[i], s)
	}
	s, err = newq2.Pop()
	assert.Error(err)
}
