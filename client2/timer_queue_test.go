package client2

import (
	"io"
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTimerQueueHalt(t *testing.T) {
	noop := func(ignored interface{}) {
		t.Log("action")
	}
	q := NewTimerQueue(noop)
	q.Start()
	surbID := [sConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbID[:])
	require.NoError(t, err)
	go q.Halt()
	q.Wait()
}

// disable time based tests because github CI cannot properly handle it
func NoTestTimerQueuePush(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	noop := func(ignored interface{}) {
		t.Log("action")
	}
	q := NewTimerQueue(noop)
	q.Start()

	for i := 0; i < 10; i++ {
		surbID := [sConstants.SURBIDLength]byte{}
		_, err := io.ReadFull(rand.Reader, surbID[:])
		assert.NoError(err)

		rtt := time.Millisecond * 50
		duration := rtt
		replyArrivalTime := time.Now().Add(duration)
		priority := uint64(replyArrivalTime.UnixNano())

		q.Push(priority, &surbID)
	}
	require.Equal(t, q.Len(), 10)
	<-time.After(200 * time.Millisecond)
	require.Equal(t, q.Len(), 0)
	go q.Halt()
	q.Wait()
}