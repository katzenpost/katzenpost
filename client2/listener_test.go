// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"errors"
	"testing"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/stretchr/testify/require"
)

func TestListenerBasic(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	client := &Client{
		cfg: cfg,
	}

	rates := &Rates{
		messageOrDrop: 555,
	}

	egressSize := 123
	egressCh := make(chan *Request, egressSize)

	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	listener, err := NewListener(client, rates, egressCh, logBackend)
	require.NoError(t, err)

	listener.connectionStatus = errors.New("fail")

	fakeappID := &[AppIDLength]byte{}

	require.Nil(t, listener.getConnection(fakeappID))

	epoch, _, _ := epochtime.Now()

	doc1 := &cpki.Document{
		Epoch:   epoch,
		LambdaP: rates.messageOrDrop,
	}

	listener.doUpdateFromPKIDoc(doc1)
	require.NotNil(t, listener.getConnectionStatus())

	listener.doUpdateConnectionStatus(nil)
	require.Nil(t, listener.getConnectionStatus())

	//listener.connectionStatus = errors.New("fail")
	//listener.updateConnectionStatus(nil)
	//time.Sleep(1 * time.Second)
	//require.Nil(t, listener.getConnectionStatus())

	listener.Shutdown()
}
