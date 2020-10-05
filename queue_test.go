package catshadow

import (
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
}
