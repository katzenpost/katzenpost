// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package cborplugin

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"
)

type testCommand struct {
	panics bool
}

func (c *testCommand) Marshal() ([]byte, error) { return nil, nil }
func (c *testCommand) Unmarshal([]byte) error   { return nil }

type recordingPlugin struct {
	handled chan *testCommand
}

func (p *recordingPlugin) OnCommand(cmd Command) error {
	c := cmd.(*testCommand)
	if c.panics {
		panic("plugin failure")
	}
	p.handled <- c
	return nil
}

func (p *recordingPlugin) RegisterConsumer(*Server) {}

func TestServerWorkerSurvivesPluginPanic(t *testing.T) {
	log := logging.MustGetLogger("cborplugin_test")
	plugin := &recordingPlugin{handled: make(chan *testCommand, 1)}
	s := &Server{
		log:    log,
		socket: NewCommandIO(log),
		plugin: plugin,
	}
	s.Go(s.worker)
	defer s.Halt()

	s.socket.ReadChan() <- &testCommand{panics: true}

	next := &testCommand{}
	select {
	case s.socket.ReadChan() <- next:
	case <-time.After(time.Second):
		t.Fatal("worker stopped reading commands after a plugin panic")
	}
	select {
	case got := <-plugin.handled:
		require.Same(t, next, got)
	case <-time.After(time.Second):
		t.Fatal("command after a plugin panic was not handled")
	}
}
