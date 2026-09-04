// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

// legacyMessageSentEvent is MessageSentEvent as it stood before the route
// fields were added. The compatibility tests below decode across the two
// shapes in both directions, so that a daemon and a thin client of different
// vintages are known to interoperate rather than assumed to.
type legacyMessageSentEvent struct {
	MessageID *[MessageIDLength]byte         `cbor:"message_id"`
	SURBID    *[sConstants.SURBIDLength]byte `cbor:"surbid"`
	SentAt    time.Time                      `cbor:"sent_at"`
	ReplyETA  time.Duration                  `cbor:"reply_eta"`
	Err       string                         `cbor:"err,omitempty"`
}

func testSURBID() *[sConstants.SURBIDLength]byte {
	id := new([sConstants.SURBIDLength]byte)
	for i := range id {
		id[i] = byte(i)
	}
	return id
}

// A new daemon's event must decode in an old thin client, which has no
// knowledge of the route fields at all.
func TestMessageSentEventNewDaemonOldClient(t *testing.T) {
	sentAt := time.Now().UTC().Truncate(time.Second)
	blob, err := cbor.Marshal(&MessageSentEvent{
		SURBID:       testSURBID(),
		SentAt:       sentAt,
		ReplyETA:     3 * time.Second,
		ForwardRoute: []string{"gw1", "mix1", "mix2", "mix3", "svc1"},
		ReturnRoute:  []string{"mix4", "mix5", "mix6", "gw1"},
	})
	require.NoError(t, err)

	old := new(legacyMessageSentEvent)
	require.NoError(t, cbor.Unmarshal(blob, old),
		"an old thin client must ignore the route fields, not fail on them")
	require.Equal(t, testSURBID(), old.SURBID)
	require.Equal(t, 3*time.Second, old.ReplyETA)
	require.True(t, sentAt.Equal(old.SentAt))
}

// An old daemon's event must decode in a new thin client, leaving the routes
// nil. Nil must be read as unknown, which is why the fields carry omitempty
// and why no caller may treat an empty route as a route of no hops.
func TestMessageSentEventOldDaemonNewClient(t *testing.T) {
	sentAt := time.Now().UTC().Truncate(time.Second)
	blob, err := cbor.Marshal(&legacyMessageSentEvent{
		SURBID:   testSURBID(),
		SentAt:   sentAt,
		ReplyETA: 3 * time.Second,
	})
	require.NoError(t, err)

	fresh := new(MessageSentEvent)
	require.NoError(t, cbor.Unmarshal(blob, fresh),
		"a new thin client must tolerate an event with no route fields")
	require.Equal(t, testSURBID(), fresh.SURBID)
	require.Equal(t, 3*time.Second, fresh.ReplyETA)
	require.True(t, sentAt.Equal(fresh.SentAt))
	require.Nil(t, fresh.ForwardRoute)
	require.Nil(t, fresh.ReturnRoute)
}

// A message sent without a SURB has no return path, which must be encoded as
// an absent field rather than an empty list, so that it costs nothing on the
// wire and reads identically to an older daemon's silence.
func TestMessageSentEventNoSURBOmitsReturnRoute(t *testing.T) {
	withRoutes, err := cbor.Marshal(&MessageSentEvent{
		SURBID:       testSURBID(),
		ForwardRoute: []string{"gw1", "mix1"},
		ReturnRoute:  []string{"mix2", "gw1"},
	})
	require.NoError(t, err)

	forwardOnly, err := cbor.Marshal(&MessageSentEvent{
		SURBID:       testSURBID(),
		ForwardRoute: []string{"gw1", "mix1"},
	})
	require.NoError(t, err)
	require.Less(t, len(forwardOnly), len(withRoutes))

	decoded := new(MessageSentEvent)
	require.NoError(t, cbor.Unmarshal(forwardOnly, decoded))
	require.Equal(t, []string{"gw1", "mix1"}, decoded.ForwardRoute)
	require.Nil(t, decoded.ReturnRoute)
}
