// client.go - client of new cbor plugin system for kaetzchen services
// Copyright (C) 2021  David Stainton, Masala
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
// https://github.com/katzenpost/katzenpost/blob/master/docs/specs/kaetzchen.rst
package cborplugin

import (
	"bufio"
	"io"
	"os/exec"
	"syscall"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/worker"
	"gopkg.in/op/go-logging.v1"
)

// Request is the struct type used in service query requests to plugins.
// This struct is backwards compatible - it contains the original fields
// at the top level, plus optional new fields for parameter requests.
// Old plugins will ignore the new fields (cbor omitempty).
// New plugins can check IsParametersRequest to handle parameter queries.
type Request struct {
	// RequestAt is the time when the Request corresponding to this Response was received
	RequestAt time.Time
	// Delay is the amount of time that the Response should be delayed before transmission
	Delay time.Duration // the Delay specififed for this hop
	// ID is the Request's packet ID
	ID uint64
	// Payload is the encrypted Request
	Payload []byte
	// SURB is the routing header used to return the Response to the requesting client
	SURB []byte

	// IsParametersRequest signals this is a request for plugin parameters,
	// not a regular service request. Old plugins ignore this field.
	IsParametersRequest bool `cbor:",omitempty"`
}

// Marshal serializes Request
func (r *Request) Marshal() ([]byte, error) {
	return cbor.Marshal(r)
}

// Unmarshal deserializes Request
func (r *Request) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, r)
}

// RequestFactory is a CommandBuilder for Requests
type RequestFactory struct {
}

// Build returns a Request
func (r *RequestFactory) Build() Command {
	return new(Request)
}

// Response is the response received after sending a Request to the plugin.
// This struct is backwards compatible - it contains the original fields
// at the top level, plus optional new fields for parameter responses.
// Old plugins send responses without the new fields.
// New plugins can set IsParametersResponse and Params for dynamic parameters.
type Response struct {
	// RequestAt is the time when the Request corresponding to this Response was received
	RequestAt time.Time
	// Delay is the amount of time that the Response should be delayed before transmission
	Delay time.Duration
	// ID is the Request's packet ID
	ID uint64
	// Payload is the encrypted response
	Payload []byte
	// SURB is the routing header used to return the Response to the requesting client
	SURB []byte

	// IsParametersResponse signals this is a response containing plugin parameters,
	// not a regular service response. Old plugins never set this field.
	IsParametersResponse bool `cbor:",omitempty"`
	// Params contains dynamic parameters from the plugin when IsParametersResponse is true.
	// This is used for plugin-advertised data in the mix descriptor.
	Params map[string]interface{} `cbor:",omitempty"`
}

// Marshal serializes Response
func (r *Response) Marshal() ([]byte, error) {
	return cbor.Marshal(r)
}

// Unmarshal deserializes Response
func (r *Response) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, r)
}

// ResponseFactory is a CommandBuilder for Responses
type ResponseFactory struct {
}

// Build returns a Response
func (r *ResponseFactory) Build() Command {
	return new(Response)
}

// IsRegularResponse returns true if this is a regular service response
// (not a parameters response). Used to distinguish response types.
func (r *Response) IsRegularResponse() bool {
	return !r.IsParametersResponse
}

// Parameters is an optional mapping that plugins can publish, these get
// advertised to clients in the MixDescriptor.
// The output of GetParameters() ends up being published in a map
// associating with the service names to service parameters map.
// This information is part of the Mix Descriptor which is defined here:
// https://github.com/katzenpost/katzenpost/blob/master/core/pki/pki.go
type Parameters map[string]string

// ServicePlugin is the interface that we expose for external
// plugins to implement. This is similar to the internal Kaetzchen
// interface defined in:
// github.com/katzenpost/katzenpost/server/internal/provider/kaetzchen/kaetzchen.go
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

	socket *CommandIO

	logBackend *log.Backend
	log        *logging.Logger

	socketFile string
	cmd        *exec.Cmd
	//conn       net.Conn

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
	err := c.cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		c.log.Errorf("CBOR plugin worker, error sending SIGTERM: %s\n", err)
	}
	err = c.cmd.Wait()
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
	// also calls Halt() when stderr closes, if the program crashes or is killed
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

// NewParametersRequest creates a Request that asks the plugin for its dynamic parameters.
// Old plugins will ignore the IsParametersRequest field and may return an empty or
// error response. New plugins should check IsParametersRequest and respond with
// a Response where IsParametersResponse=true and Params is populated.
func NewParametersRequest() *Request {
	return &Request{
		IsParametersRequest: true,
	}
}

// NewParametersResponse creates a Response containing dynamic plugin parameters.
// This is used by new plugins to advertise dynamic data to the mix descriptor.
func NewParametersResponse(params map[string]interface{}) *Response {
	return &Response{
		IsParametersResponse: true,
		Params:               params,
	}
}
