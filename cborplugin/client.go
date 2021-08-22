// client.go - client of cbor plugin system
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
	"bufio"
	"io"
	"net"
	"os/exec"
	"syscall"

	"github.com/fxamacker/cbor/v2"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/worker"
)

type Client struct {
	worker.Worker

	logBackend *log.Backend
	log        *logging.Logger
	conn       net.Conn
	cmd        *exec.Cmd
	socketPath string
	endpoint   string
	capability string
	params     *Parameters
}

// New creates a new plugin client instance which represents the single execution
// of the external plugin program.
func NewClient(command, capability, endpoint string, logBackend *log.Backend) *Client {
	return &Client{
		capability: capability,
		endpoint:   endpoint,
		logBackend: logBackend,
		log:        logBackend.GetLogger(command),
	}
}

// Start execs the plugin and starts a worker thread to listen
// on the halt chan sends a TERM signal to the plugin if the shutdown
// even is dispatched.
func (c *Client) Start(command string, args []string) error {
	err := c.launch(command, args)
	if err != nil {
		return err
	}
	c.Go(c.worker)
	return nil
}

func (c *Client) dialSocket(socketPath string) error {
	var err error
	c.conn, err = net.Dial("unix", socketPath)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) worker() {
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
	c.socketPath = stdoutScanner.Text()
	c.log.Debugf("plugin socket path:'%s'\n", c.socketPath)
	c.dialSocket(c.socketPath)

	c.log.Debug("finished launching plugin.")
	return nil
}

func (c *Client) readResponse() ([]byte, error) {
	response := new(Response)
	err := readCommand(c.conn, response)
	if err != nil {
		return nil, err
	}

	return response.Payload, nil
}

func (c *Client) writeRequest(request PluginCommand) error {
	return writeCommand(c.conn, request)
}

// OnRequest send a query request to plugin using length prefix CBOR over Unix domain socket.
func (c *Client) OnRequest(request PluginCommand) ([]byte, error) {
	if err := c.writeRequest(request); err != nil {
		return nil, err
	}

	response, err := c.readResponse()
	if err != nil {
		return nil, err
	}
	return response, nil
}

// Capability are used in Mix Descriptor publication to give
// service clients more information about the service.
func (c *Client) Capability() string {
	return c.capability
}

// GetParameters are used in Mix Descriptor publication to give
// service clients more information about the service. Not
// plugins will need to use this feature.
func (c *Client) GetParameters() (*Parameters, error) {
	// get plugin parameters if any
	c.log.Debug("requesting plugin Parameters for Mix Descriptor publication...")

	request := &Request{
		GetParameters: true,
	}
	err := c.writeRequest(request)
	if err != nil {
		c.log.Debugf("sending of getParameters failure: %s", err)
		c.Halt()
		return nil, err
	}

	response, err := c.readResponse()
	if err != nil {
		return nil, err
	}

	responseParams := make(Parameters)
	err = cbor.Unmarshal(response, responseParams)
	if err != nil {
		c.log.Debugf("decode failure: %s", err)
		return nil, err
	}
	// XXX: why does this happen?
	if responseParams == nil {
		c.log.Debugf("no parameters set for %s", c.capability)
		responseParams = make(Parameters)
	}
	responseParams["endpoint"] = c.endpoint
	return &responseParams, nil
}
