package client2

import (
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/stretchr/testify/require"
)

func TestTimerQueue(t *testing.T) {
	noop := func(ignored interface{}) {
		t.Log("action")
	}
	q := NewTimerQueue(noop)
	q.Start()
	surbID := [sConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbID[:])
	require.NoError(t, err)
	q.Push(uint64(time.Now().UnixNano()), &surbID)
	q.Halt()
	require.Equal(t, 0, q.queue.Len())
}
