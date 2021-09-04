// client.go - client of new cbor plugin system for kaetzchen services
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
// the mix server using CBOR over UNIX domain socket. Beyond that,
// a client supplied SURB is used to route the response back to the client
// as described in our Kaetzchen specification document:
//
// https://github.com/katzenpost/docs/blob/master/specs/kaetzchen.rst
//
package cborplugin

import (
	"bufio"
	"io"
	"net"
	"os/exec"
	"syscall"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/worker"
)

type Client struct {
	worker.Worker

	socket *CommandIO

	logBackend *log.Backend
	log        *logging.Logger

	socketFile string
	cmd        *exec.Cmd
	conn       net.Conn

	commandBuilder CommandBuilder

	capability string
	endpoint   string
}

// New creates a new plugin client instance which represents the single execution
// of the external plugin program.

func NewClient(logBackend *log.Backend, capability, endpoint string, commandBuilder CommandBuilder) *Client {
	return &Client{
		socket:         NewCommandIO(logBackend.GetLogger("client_socket")),
		logBackend:     logBackend,
		log:            logBackend.GetLogger("client"),
		commandBuilder: commandBuilder,
		capability:     capability,
		endpoint:       endpoint,
	}
}

func (c *Client) Capability() string {
	return c.capability
}

func (c *Client) GetParameters() *map[string]interface{} {
	responseParams := make(map[string]interface{})
	responseParams["endpoint"] = c.endpoint
	return &responseParams
}

// Start execs the plugin and starts a worker thread to listen
// on the halt chan sends a TERM signal to the plugin if the shutdown
// even is dispatched.
func (c *Client) Start(command string, args []string) error {
	err := c.launch(command, args)
	if err != nil {
		return err
	}
	c.Go(c.reaper)
	c.socket.Start(true, c.socketFile, c.commandBuilder)
	return nil
}

func (c *Client) reaper() {
	<-c.HaltCh()
	c.cmd.Process.Signal(syscall.SIGTERM)
	err := c.cmd.Wait()
	if err != nil {
		c.log.Errorf("CBOR plugin worker, command exec error: %s\n", err)
	}
}

func (c *Client) logPluginStderr(stderr io.ReadCloser) {
	logWriter := c.logBackend.GetLogWriter(c.cmd.Path, "DEBUG")
	_, err := io.Copy(logWriter, stderr)
	if err != nil {
		c.log.Errorf("Failed to proxy cborplugin stderr to DEBUG log: %s", err)
	}
	c.Halt()
}

func (c *Client) launch(command string, args []string) error {
	// exec plugin
	c.cmd = exec.Command(command, args...)
	stdout, err := c.cmd.StdoutPipe()
	if err != nil {
		c.log.Debugf("pipe failure: %s", err)
		return err
	}
	stderr, err := c.cmd.StderrPipe()
	if err != nil {
		c.log.Debugf("pipe failure: %s", err)
		return err
	}
	err = c.cmd.Start()
	if err != nil {
		c.log.Debugf("failed to exec: %s", err)
		return err
	}

	// proxy stderr to our debug log
	c.Go(func() {
		c.logPluginStderr(stderr)
	})

	// read and decode plugin stdout
	stdoutScanner := bufio.NewScanner(stdout)
	stdoutScanner.Scan()
	c.socketFile = stdoutScanner.Text()
	c.log.Debugf("plugin socket path:'%s'\n", c.socketFile)
	return nil
}

func (c *Client) ReadChan() chan Command {
	return c.socket.ReadChan()
}

func (c *Client) WriteChan() chan Command {
	return c.socket.WriteChan()
}
