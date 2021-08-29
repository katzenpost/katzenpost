// client.go - client of cbor plugin system for katzenpost clients
// Copyright (C) 2021  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package cborplugin is a plugin system allowing mix network services
// to be added in any language. It communicates queries and responses to and from
// the mix server using CBOR over HTTP over UNIX domain socket. Beyond that,
// a client supplied SURB is used to route the response back to the client
// as described in our Kaetzchen specification document:
//
// https://github.com/katzenpost/docs/blob/master/specs/kaetzchen.rst
//
package cborplugin

import (
	"context"
	"io"

	"golang.org/x/sync/errgroup"
	"gopkg.in/op/go-logging.v1"

	cConstants "github.com/katzenpost/client/constants"
	"github.com/katzenpost/core/cborplugin"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
)

type Session interface {
	SendMessage(recipient, provider string, message []byte, ID [cConstants.MessageIDLength]byte) error
}

type Client struct {
	cborplugin.Client

	session Session

	log        *logging.Logger
	ctx        context.Context
	cancelFunc context.CancelFunc
	group      *errgroup.Group
}

// New creates a new plugin client instance which represents the single execution
// of the external plugin program.
func New(session Session, logBackend *log.Backend) *Client {
	ctx := context.Background()
	ctx, cancelFunc := context.WithCancel(ctx)

	group, _ := errgroup.WithContext(ctx)
	c := &Client{
		Client:     *(cborplugin.NewClient(logBackend, &EventBuilder{})),
		ctx:        ctx,
		cancelFunc: cancelFunc,
		group:      group,
		log:        logBackend.GetLogger("client"),
	}
	c.group.Go(c.worker)
	return c
}

func (c *Client) worker() error {
	for {
		select {
		case <-c.ctx.Done():
			return nil
		case cmd := <-c.ReadChan():
			command, ok := cmd.(*Command)
			if !ok {
				c.log.Error("failure to type assert command received from plugin")
				continue
			}
			c.processCommand(command)
		}
	}

	return nil
}

func (c *Client) Halt() {
	c.cancelFunc()
	c.group.Wait()
}

func (c *Client) processCommand(command *Command) {
	if command.SendMessage != nil && command.CreateRemoteSpool != nil {
		c.log.Error("only one command at a time")
		return
	}
	if command.SendMessage == nil && command.CreateRemoteSpool == nil {
		c.log.Error("at least one command is required")
		return
	}

	if command.SendMessage != nil {
		id := [cConstants.MessageIDLength]byte{}
		_, err := io.ReadFull(rand.Reader, id[:])
		if err != nil {
			c.log.Error(err.Error())
		}

		// TODO(david): Use the message id to route this message's reply to this plugin.

		err = c.session.SendMessage(command.SendMessage.Recipient, command.SendMessage.Provider, command.SendMessage.Payload, id)
		if err != nil {
			c.log.Error(err.Error())
		}

		return
	}

	/*
		type CreateRemoteSpool struct {
			Recipient string
			Provider  string
			SpoolID   []byte
		}
	*/
	if command.CreateRemoteSpool != nil {
		panic("CreateRemoteSpool not yet implemented")
		return
	}
}
