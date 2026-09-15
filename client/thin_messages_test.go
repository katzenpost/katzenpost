// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/thin"
)

func TestFromThinRequestNewKeypair(t *testing.T) {
	appID := new([AppIDLength]byte)
	appID[0] = 42
	queryID := new([thin.QueryIDLength]byte)
	seed := []byte("test-seed")

	thinReq := &thin.Request{
		NewKeypair: &thin.NewKeypair{
			QueryID: queryID,
			Seed:    seed,
		},
	}

	req := FromThinRequest(thinReq, appID)

	require.Equal(t, appID, req.AppID)
	require.NotNil(t, req.NewKeypair)
	require.Equal(t, queryID, req.NewKeypair.QueryID)
	require.Equal(t, seed, req.NewKeypair.Seed)
	require.Nil(t, req.EncryptRead)
	require.Nil(t, req.SendMessage)
	require.Nil(t, req.ThinClose)
}

func TestFromThinRequestThinClose(t *testing.T) {
	appID := new([AppIDLength]byte)
	thinReq := &thin.Request{
		ThinClose: &thin.ThinClose{},
	}

	req := FromThinRequest(thinReq, appID)

	require.Equal(t, appID, req.AppID)
	require.NotNil(t, req.ThinClose)
	require.Nil(t, req.NewKeypair)
}

func TestFromThinRequestNilFields(t *testing.T) {
	appID := new([AppIDLength]byte)
	thinReq := &thin.Request{}

	req := FromThinRequest(thinReq, appID)

	require.Equal(t, appID, req.AppID)
	require.Nil(t, req.NewKeypair)
	require.Nil(t, req.EncryptRead)
	require.Nil(t, req.EncryptWrite)
	require.Nil(t, req.SendMessage)
	require.Nil(t, req.ThinClose)
}
