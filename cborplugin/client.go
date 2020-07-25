// client.go - client of cbor plugin system for kaetzchen services
// Copyright (C) 2018  David Stainton.
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
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os/exec"
	"syscall"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/worker"
	"gopkg.in/op/go-logging.v1"
)

// Request is the struct type used in service query requests to plugins.
type Request struct {
	ID      uint64
	Payload []byte
	HasSURB bool
}

// Response is the response received after sending a Request to the plugin.
type Response struct {
	Payload []byte
}

// Parameters is an optional mapping that plugins can publish, these get
// advertised to clients in the MixDescriptor.
// The output of GetParameters() ends up being published in a map
// associating with the service names to service parameters map.
// This information is part of the Mix Descriptor which is defined here:
// https://github.com/katzenpost/core/blob/master/pki/pki.go
type Parameters map[string]string

// ServicePlugin is the interface that we expose for external
// plugins to implement. This is similar to the internal Kaetzchen
// interface defined in:
// github.com/katzenpost/server/internal/provider/kaetzchen/kaetzchen.go
type ServicePlugin interface {
	// OnRequest is the method that is called when the Provider receives
	// a request designed for a particular agent. The caller will handle
	// extracting the payload component of the message
	OnRequest(request *Request) ([]byte, error)

	// Capability returns the agent's functionality for publication in
	// the Provider's descriptor.
	Capability() string

	// Parameters returns the agent's paramenters for publication in
	// the Provider's descriptor.
	GetParameters() *Parameters

	// Halt stops the plugin.
	Halt()
}

// Client acts as a client interacting with one or more plugins.
// The Client type is composite with Worker and therefore
// has a Halt method. Client implements this interface
// and proxies data between this mix server and the
// external plugin program.
type Client struct {
	worker.Worker

	logBackend *log.Backend
	log        *logging.Logger
	httpClient *http.Client
	cmd        *exec.Cmd
	socketPath string
	endpoint   string
	capability string
	params     *Parameters
}

// New creates a new plugin client instance which represents the single execution
// of the external plugin program.
func New(command, capability, endpoint string, logBackend *log.Backend) *Client {
	return &Client{
		capability: capability,
		endpoint:   endpoint,
		logBackend: logBackend,
		log:        logBackend.GetLogger(command),
		httpClient: nil,
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

func (c *Client) worker() {
	<-c.HaltCh()
	c.cmd.Process.Signal(syscall.SIGTERM)
	err := c.cmd.Wait()
	if err != nil {
		c.log.Errorf("CBOR plugin worker, command exec error: %s\n", err)
	}
}

func (c *Client) setupHTTPClient(socketPath string) {
	c.httpClient = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return new(net.Dialer).DialContext(ctx, "unix", socketPath)
			},
		},
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
	c.setupHTTPClient(c.socketPath)

	c.log.Debug("finished launching plugin.")
	return nil
}

// OnRequest send a query request to plugin using CBOR + HTTP over Unix domain socket.
func (c *Client) OnRequest(request *Request) ([]byte, error) {
	serialized, err := cbor.Marshal(request)
	if err != nil {
		return nil, err
	}

	rawResponse, err := c.httpClient.Post("http://unix/request", "application/octet-stream", bytes.NewReader(serialized))
	if err != nil {
		return nil, err
	}
	response := new(Response)
	decoder := cbor.NewDecoder(rawResponse.Body)
	err = decoder.Decode(&response)
	if err != nil {
		return nil, err
	}
	return response.Payload, nil
}

// Capability are used in Mix Descriptor publication to give
// service clients more information about the service. Not
// plugins will need to use this feature.
func (c *Client) Capability() string {
	return c.capability
}

// GetParameters are used in Mix Descriptor publication to give
// service clients more information about the service. Not
// plugins will need to use this feature.
func (c *Client) GetParameters() *Parameters {
	// get plugin parameters if any
	c.log.Debug("requesting plugin Parameters for Mix Descriptor publication...")
	rawResponse, err := c.httpClient.Post("http://unix/parameters", "application/octet-stream", http.NoBody)
	if err != nil {
		c.log.Debugf("post failure: %s", err)
		c.Halt()
		return nil
	}
	responseParams := make(Parameters)
	decoder := cbor.NewDecoder(rawResponse.Body)
	err = decoder.Decode(&responseParams)
	if err != nil {
		c.log.Debugf("decode failure: %s", err)
		return nil
	}
	// XXX: why does this happen?
	if responseParams == nil {
		c.log.Debugf("no parameters set for %s", c.capability)
		responseParams = make(Parameters)
	}
	responseParams["endpoint"] = c.endpoint
	return &responseParams
}
