// SPDX-License-Identifier: AGPL-3.0-only

package memspool

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

type ignoreSet = map[[sConstants.RecipientIDLength]byte]interface{}

func surbID(b byte) *[sConstants.SURBIDLength]byte {
	var id [sConstants.SURBIDLength]byte
	id[0] = b
	return &id
}

func key(u string) [sConstants.RecipientIDLength]byte {
	var k [sConstants.RecipientIDLength]byte
	copy(k[:], u)
	return k
}

// requireGet checks one Get call; a nil wantMsg means an empty spool.
func requireGet(t *testing.T, s interface {
	Get([]byte, bool) ([]byte, []byte, int, error)
}, u string, advance bool, wantMsg string, wantID *[sConstants.SURBIDLength]byte, wantRemaining int) {
	t.Helper()
	msg, id, remaining, err := s.Get([]byte(u), advance)
	require.NoError(t, err)
	if wantMsg == "" {
		require.Nil(t, msg)
	} else {
		require.Equal(t, []byte(wantMsg), msg)
	}
	if wantID == nil {
		require.Nil(t, id)
	} else {
		require.Equal(t, wantID[:], id)
	}
	require.Equal(t, wantRemaining, remaining)
}

// The scenario of the old boltspool test.
func TestStoreAndGet(t *testing.T) {
	s := New()
	defer s.Close()
	const u = "allan"

	require.NoError(t, s.StoreMessage([]byte(u), []byte("msg")))
	require.NoError(t, s.StoreSURBReply([]byte(u), surbID(1), []byte("surb")))

	requireGet(t, s, u, false, "msg", nil, 1)
	// Advance past the message, then peek: both return the SURB reply.
	requireGet(t, s, u, true, "surb", surbID(1), 0)
	requireGet(t, s, u, false, "surb", surbID(1), 0)
	// Advancing past the last entry returns nothing.
	requireGet(t, s, u, true, "", nil, 0)
	require.NoError(t, s.Remove([]byte(u)))
}

func TestAdvanceAndRemaining(t *testing.T) {
	s := New()
	defer s.Close()
	const u = "u"

	requireGet(t, s, u, false, "", nil, 0)
	requireGet(t, s, u, true, "", nil, 0)

	for i := 0; i < 3; i++ {
		require.NoError(t, s.StoreMessage([]byte(u), []byte(fmt.Sprint(i))))
	}
	// remaining is a hint: 1 while more than the returned entry is queued.
	requireGet(t, s, u, false, "0", nil, 1)
	requireGet(t, s, u, false, "0", nil, 1)
	requireGet(t, s, u, true, "1", nil, 1)
	requireGet(t, s, u, true, "2", nil, 0)
	requireGet(t, s, u, true, "", nil, 0)
	requireGet(t, s, u, true, "", nil, 0)

	// A drained spool takes new entries again, in order.
	require.NoError(t, s.StoreMessage([]byte(u), []byte("a")))
	require.NoError(t, s.StoreMessage([]byte(u), []byte("b")))
	requireGet(t, s, u, false, "a", nil, 1)
	requireGet(t, s, u, true, "b", nil, 0)
}

func TestSURBIDs(t *testing.T) {
	s := New()
	defer s.Close()
	const u = "u"

	require.EqualError(t, s.StoreSURBReply([]byte(u), nil, []byte("x")), "spool: SURBReply is missing ID")
	requireGet(t, s, u, false, "", nil, 0)

	require.NoError(t, s.StoreSURBReply([]byte(u), surbID(1), []byte("r1")))
	require.NoError(t, s.StoreMessage([]byte(u), []byte("m")))
	require.NoError(t, s.StoreSURBReply([]byte(u), surbID(2), []byte("r2")))
	requireGet(t, s, u, false, "r1", surbID(1), 1)
	requireGet(t, s, u, true, "m", nil, 1)
	requireGet(t, s, u, true, "r2", surbID(2), 0)
}

func TestInvalidUsername(t *testing.T) {
	s := New()
	defer s.Close()
	for _, u := range [][]byte{nil, {}, make([]byte, sConstants.RecipientIDLength+1)} {
		require.EqualError(t, s.StoreMessage(u, []byte("m")), fmt.Sprintf("spool: invalid username: `%v`", u))
		require.EqualError(t, s.StoreSURBReply(u, surbID(1), []byte("m")), fmt.Sprintf("spool: invalid username: `%v`", u))
	}
	require.NoError(t, s.StoreMessage(make([]byte, sConstants.RecipientIDLength), []byte("m")))
}

func TestUsersAreSeparate(t *testing.T) {
	s := New()
	defer s.Close()
	require.NoError(t, s.StoreMessage([]byte("a"), []byte("for a")))
	require.NoError(t, s.StoreMessage([]byte("b"), []byte("for b")))
	requireGet(t, s, "a", true, "", nil, 0)
	requireGet(t, s, "b", false, "for b", nil, 0)
	require.NoError(t, s.Remove([]byte("b")))
	require.NoError(t, s.Remove([]byte("b")), "removing a missing user is not an error")
	requireGet(t, s, "b", false, "", nil, 0)
}

func TestVacuumExpired(t *testing.T) {
	s := New()
	defer s.Close()
	for _, u := range []string{"keep", "drop", "also-drop"} {
		require.NoError(t, s.StoreMessage([]byte(u), []byte(u)))
	}
	// A short ID matches its zero-padded form in the ignore set.
	require.NoError(t, s.VacuumExpired(ignoreSet{key("keep"): nil}))
	requireGet(t, s, "keep", false, "keep", nil, 0)
	requireGet(t, s, "drop", false, "", nil, 0)
	requireGet(t, s, "also-drop", false, "", nil, 0)

	require.NoError(t, s.VacuumExpired(nil))
	requireGet(t, s, "keep", false, "", nil, 0)
}

func TestCopies(t *testing.T) {
	s := New()
	defer s.Close()
	in := []byte("abc")
	id := surbID(9)
	require.NoError(t, s.StoreSURBReply([]byte("u"), id, in))
	in[0], id[0] = 'X', 0 // the caller reuses its buffers

	msg, gotID, _, err := s.Get([]byte("u"), false)
	require.NoError(t, err)
	msg[1], gotID[1] = 'X', 1 // the caller modifies what it got
	requireGet(t, s, "u", false, "abc", surbID(9), 0)
}

func TestClosed(t *testing.T) {
	s := New()
	require.NoError(t, s.StoreMessage([]byte("u"), []byte("m")))
	s.Close()
	require.Error(t, s.StoreMessage([]byte("u"), []byte("m")))
	_, _, _, err := s.Get([]byte("u"), false)
	require.Error(t, err)
	require.Error(t, s.Remove([]byte("u")))
	require.Error(t, s.VacuumExpired(nil))
	s.Close()
}

// Run with -race: stores, gets, removes and vacuums from many goroutines.
func TestConcurrent(t *testing.T) {
	s := New()
	defer s.Close()
	const users, perUser = 8, 200
	var wg sync.WaitGroup
	for i := 0; i < users; i++ {
		u := []byte{byte(i + 1)}
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < perUser; j++ {
				require.NoError(t, s.StoreMessage(u, []byte{byte(j)}))
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < perUser; j++ {
				_, _, _, err := s.Get(u, j%2 == 0)
				require.NoError(t, err)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 50; j++ {
			require.NoError(t, s.VacuumExpired(ignoreSet{key("\x01"): nil}))
			require.NoError(t, s.Remove([]byte{2}))
		}
	}()
	wg.Wait()
}
