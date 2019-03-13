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
// as described in our Kaetzchen specification document.
package cborplugin

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"syscall"

	"github.com/katzenpost/core/worker"
	"github.com/ugorji/go/codec"
	"gopkg.in/op/go-logging.v1"
)

// ServicePlugin is the interface that we expose for external
// plugins to implement. This is similar to the internal Kaetzchen
// interface defined in:
// github.com/katzenpost/server/internal/provider/kaetzchen/kaetzchen.go
type ServicePlugin interface {
	// OnRequest is the method that is called when the Provider receives
	// a request desgined for a particular agent. The caller will handle
	// extracting the payload component of the message
	OnRequest(id uint64, request []byte, hasSURB bool) ([]byte, error)

	// Parameters returns the agent's paramenters for publication in
	// the Provider's descriptor.
	Parameters() map[string]string

	Halt()
}

// Request is the struct type used in service query requests to plugins.
type Request struct {
	ID      uint64
	HasSURB bool
	Payload []byte
}

// Response is the response received after sending a Request to the plugin.
type Response struct {
	Payload []byte
}

// Parameters is an optional mapping that plugins can publish, these get
// advertised to clients in the MixDescriptor.
type Parameters struct {
	Map map[string]string
}

// Client acts as a client interacting with one or more plugins.
type Client struct {
	worker.Worker

	log *logging.Logger

	httpClient *http.Client
	cmd        *exec.Cmd
	socketPath string
	params     map[string]string
}

// New creates a new plugin client instance which represents the single execution
// of the external plugin program.
func New(log *logging.Logger) *Client {
	return &Client{
		log:        log,
		httpClient: nil,
	}
}

// Start execs the plugin and starts a worker thread to listen
// on the halt chan sends a HUP to the plugin if the shutdown
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
	c.cmd.Process.Signal(syscall.SIGHUP)
	err := c.cmd.Wait()
	if err != nil {
		c.log.Errorf("CBOR plugin worker, command exec error: %s\n", err)
	}
}

func (c *Client) dial(socketPath string) {
	c.httpClient = &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}
}

func (c *Client) launch(command string, args []string) error {
	// exec plugin
	if args == nil {
		c.cmd = exec.Command(command)
	} else {
		c.cmd = exec.Command(command, args...)
	}
	stdout, err := c.cmd.StdoutPipe()
	if err != nil {
		return err
	}
	err = c.cmd.Start()
	if err != nil {
		return err
	}

	// read and decode plugin stdout
	line := make([]byte, 255)
	n, err := stdout.Read(line)
	if err != nil {
		return err
	}
	socketPath := strings.TrimSuffix(string(line[:n]), "\n")
	c.socketPath = socketPath
	c.log.Debugf("plugin socket path:'%s'\n", socketPath)

	c.dial(c.socketPath)
	c.log.Debug("requesting plugin Parameters for Mix Descriptor publication...")
	err = c.getParams()
	if err != nil {
		panic(err)
	}
	return nil
}

func (c *Client) getParams() error {
	rawResponse, err := c.httpClient.Post("http://unix/parameters", "application/octet-stream", bytes.NewBuffer([]byte{}))
	if err != nil {
		return err
	}
	response := Parameters{}
	err = codec.NewDecoder(rawResponse.Body, new(codec.CborHandle)).Decode(&response)
	if err != nil {
		return err
	}
	c.params = response.Map
	return nil
}

// OnRequest send a query request to plugin using CBOR + HTTP over Unix domain socket.
func (c *Client) OnRequest(id uint64, payload []byte, hasSURB bool) ([]byte, error) {
	request := Request{
		ID:      id,
		Payload: payload,
		HasSURB: hasSURB,
	}
	var serialized []byte
	enc := codec.NewEncoderBytes(&serialized, new(codec.CborHandle))
	if err := enc.Encode(request); err != nil {
		return nil, err
	}
	rawResponse, err := c.httpClient.Post("http://unix/request", "application/octet-stream", bytes.NewBuffer(serialized))
	if err != nil {
		return nil, err
	}
	response := Response{
		Payload: []byte{},
	}
	err = codec.NewDecoder(rawResponse.Body, new(codec.CborHandle)).Decode(&response)
	if err != nil {
		return nil, err
	}
	return response.Payload, nil
}

// Parameters are used in Mix Descriptor publication to give
// service clients more information about the service. Not
// plugins will need to use this feature.
func (c *Client) Parameters() map[string]string {
	return c.params
}
