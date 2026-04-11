// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"testing"

	"github.com/stretchr/testify/require"

	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
)

func TestFindServices(t *testing.T) {
	doc := &cpki.Document{
		ServiceNodes: []*cpki.MixDescriptor{
			{
				Name:        "service1",
				IdentityKey: []byte("identity-key-for-service1-12345!"),
				Kaetzchen: map[string]map[string]interface{}{
					"echo":    {"endpoint": "echo"},
					"courier": {"endpoint": "courier1"},
				},
			},
			{
				Name:        "service2",
				IdentityKey: []byte("identity-key-for-service2-12345!"),
				Kaetzchen: map[string]map[string]interface{}{
					"courier": {"endpoint": "courier2"},
				},
			},
			{
				Name:        "service3",
				IdentityKey: []byte("identity-key-for-service3-12345!"),
				Kaetzchen: map[string]map[string]interface{}{
					"echo": {"endpoint": "echo3"},
				},
			},
		},
	}

	t.Run("find courier services", func(t *testing.T) {
		services := FindServices("courier", doc)
		require.Len(t, services, 2)
		require.Equal(t, []byte("courier1"), services[0].RecipientQueueID)
		require.Equal(t, []byte("courier2"), services[1].RecipientQueueID)
	})

	t.Run("find echo services", func(t *testing.T) {
		services := FindServices("echo", doc)
		require.Len(t, services, 2)
	})

	t.Run("find nonexistent service", func(t *testing.T) {
		services := FindServices("nonexistent", doc)
		require.Len(t, services, 0)
	})

	t.Run("empty service nodes", func(t *testing.T) {
		emptyDoc := &cpki.Document{
			ServiceNodes: []*cpki.MixDescriptor{},
		}
		services := FindServices("courier", emptyDoc)
		require.Len(t, services, 0)
	})

	t.Run("nil doc panics", func(t *testing.T) {
		require.Panics(t, func() {
			FindServices("echo", nil)
		})
	})
}

func TestNewSURBID(t *testing.T) {
	id1 := NewSURBID()
	require.NotNil(t, id1)
	require.Len(t, id1, constants.SURBIDLength)

	id2 := NewSURBID()
	require.NotNil(t, id2)

	// Two random IDs should be different
	require.NotEqual(t, id1, id2)
}
