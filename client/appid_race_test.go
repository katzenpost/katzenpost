package client

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/log"
)

// TestIncomingConnAppIDRace races currentAppID against handleSessionToken.
func TestIncomingConnAppIDRace(t *testing.T) {
	logBackend, err := log.New("", "error", false)
	require.NoError(t, err)
	l := &listener{
		conns:                make(map[[AppIDLength]byte]*incomingConn),
		connsLock:            new(sync.RWMutex),
		clientTokens:         make(map[[16]byte]*[AppIDLength]byte),
		disconnectedSessions: make(map[[AppIDLength]byte]*DisconnectedSession),
		sessionGracePeriod:   defaultSessionGracePeriod,
		logBackend:           logBackend,
	}
	l.log = logBackend.GetLogger("test")

	oldAppID := &[AppIDLength]byte{1}
	newAppID := &[AppIDLength]byte{2}
	token := [16]byte{9}
	l.clientTokens[token] = oldAppID

	c := &incomingConn{
		listener: l,
		appID:    newAppID,
		sendWake: make(chan struct{}, 1),
		doneCh:   make(chan struct{}),
		log:      logBackend.GetLogger("test"),
	}
	l.conns[*newAppID] = c

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = c.currentAppID()
			}
		}
	}()

	for i := 0; i < 500; i++ {
		l.handleSessionToken(c, &thin.SessionToken{ClientInstanceToken: token})
	}
	close(stop)
	wg.Wait()

	require.Equal(t, oldAppID, c.currentAppID())
}
