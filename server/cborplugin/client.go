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
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/worker"
	"gopkg.in/op/go-logging.v1"
)

// Process represents a running process that can be signaled and waited on
type Process interface {
	Signal(os.Signal) error
	Wait() error
	StdoutPipe() (io.ReadCloser, error)
	StderrPipe() (io.ReadCloser, error)
	Start() error
	Path() string
}

// ProcessFactory creates Process instances
type ProcessFactory interface {
	NewProcess(command string, args []string) Process
}

// ExecProcess wraps exec.Cmd to implement Process interface
type ExecProcess struct {
	cmd *exec.Cmd
}

func (p *ExecProcess) Signal(sig os.Signal) error {
	return p.cmd.Process.Signal(sig)
}

func (p *ExecProcess) Wait() error {
	return p.cmd.Wait()
}

func (p *ExecProcess) StdoutPipe() (io.ReadCloser, error) {
	return p.cmd.StdoutPipe()
}

func (p *ExecProcess) StderrPipe() (io.ReadCloser, error) {
	return p.cmd.StderrPipe()
}

func (p *ExecProcess) Start() error {
	return p.cmd.Start()
}

func (p *ExecProcess) Path() string {
	return p.cmd.Path
}

// ExecProcessFactory is the default ProcessFactory using exec.Command
type ExecProcessFactory struct{}

func (f *ExecProcessFactory) NewProcess(command string, args []string) Process {
	return &ExecProcess{cmd: exec.Command(command, args...)}
}

// Request is the struct type used in service query requests to plugins.
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
}

// Marshal serializes Request
func (r *Request) Marshal() ([]byte, error) {
	return cbor.Marshal(r)
}

// Unmarshal deserializes Request
func (r *Request) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, r)
}

// Response is the response received after sending a Request to the plugin
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
}

// Marshal serializes Response
func (r *Response) Marshal() ([]byte, error) {
	return cbor.Marshal(r)
}

// Unmarshal deserializes Response
func (r *Response) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, r)
}

// ParametersRequest is sent by the service node to request dynamic parameters from a plugin
type ParametersRequest struct {
	// RequestID is used to correlate requests with responses
	RequestID uint64
}

// ParametersResponse is sent by the plugin in response to a ParametersRequest
type ParametersResponse struct {
	// RequestID is used to correlate requests with responses
	RequestID uint64
	// Params contains the dynamic parameters from the plugin
	Params Parameters
}

// RequestMessage is sent from the service node to the plugin.
// Only one field should be non-nil at a time.
type RequestMessage struct {
	Request           *Request
	ParametersRequest *ParametersRequest
}

// Marshal serializes RequestMessage
func (m *RequestMessage) Marshal() ([]byte, error) {
	return cbor.Marshal(m)
}

// Unmarshal deserializes RequestMessage
func (m *RequestMessage) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, m)
}

// RequestMessageFactory is a CommandBuilder for RequestMessages (used by plugins)
type RequestMessageFactory struct {
}

// Build returns a RequestMessage
func (m *RequestMessageFactory) Build() Command {
	return new(RequestMessage)
}

// ResponseMessage is sent from the plugin to the service node.
// Only one field should be non-nil at a time.
type ResponseMessage struct {
	Response           *Response
	ParametersResponse *ParametersResponse
}

// Marshal serializes ResponseMessage
func (m *ResponseMessage) Marshal() ([]byte, error) {
	return cbor.Marshal(m)
}

// Unmarshal deserializes ResponseMessage
func (m *ResponseMessage) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, m)
}

// ResponseMessageFactory is a CommandBuilder for ResponseMessages (used by service node)
type ResponseMessageFactory struct {
}

// Build returns a ResponseMessage
func (m *ResponseMessageFactory) Build() Command {
	return new(ResponseMessage)
}

// Parameters is an optional mapping that plugins can publish, these get
// advertised to clients in the MixDescriptor.
// The output of GetParameters() ends up being published in a map
// associating with the service names to service parameters map.
// This information is part of the Mix Descriptor which is defined here:
// https://github.com/katzenpost/katzenpost/blob/master/core/pki/pki.go
type Parameters map[string]interface{}

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

	socketFile     string
	process        Process
	processFactory ProcessFactory

	commandBuilder CommandBuilder

	capability string
	endpoint   string

	// For parameter requests
	paramRequestID  uint64
	paramResponseCh chan *ParametersResponse
	cachedParams    Parameters
	mu              sync.Mutex
}

// NewClient creates a new plugin client instance which represents the single execution
// of the external plugin program.
func NewClient(logBackend *log.Backend, capability, endpoint string, commandBuilder CommandBuilder) *Client {
	return &Client{
		socket:          NewCommandIO(logBackend.GetLogger("client_socket")),
		logBackend:      logBackend,
		log:             logBackend.GetLogger("client"),
		commandBuilder:  commandBuilder,
		capability:      capability,
		endpoint:        endpoint,
		paramResponseCh: make(chan *ParametersResponse, 1),
		processFactory:  &ExecProcessFactory{},
	}
}

func (c *Client) Capability() string {
	return c.capability
}

// GetParameters returns static parameters (endpoint) merged with any cached dynamic parameters.
// Use RequestParameters() to fetch fresh dynamic parameters from the plugin.
func (c *Client) GetParameters() *map[string]interface{} {
	responseParams := make(map[string]interface{})
	responseParams["endpoint"] = c.endpoint

	// Merge in any cached dynamic parameters from the plugin
	c.mu.Lock()
	for k, v := range c.cachedParams {
		responseParams[k] = v
	}
	c.mu.Unlock()

	return &responseParams
}

// RequestParameters sends a ParametersRequest to the plugin and waits for the response.
// The response is cached and merged into GetParameters() results.
func (c *Client) RequestParameters() (Parameters, error) {
	c.mu.Lock()
	c.paramRequestID++
	reqID := c.paramRequestID
	c.mu.Unlock()

	// Send the request
	msg := &RequestMessage{
		ParametersRequest: &ParametersRequest{
			RequestID: reqID,
		},
	}
	c.WriteChan() <- msg

	// Wait for response with timeout
	select {
	case resp := <-c.paramResponseCh:
		if resp.RequestID == reqID {
			c.mu.Lock()
			c.cachedParams = resp.Params
			c.mu.Unlock()
			return resp.Params, nil
		}
		c.log.Warningf("Received ParametersResponse with unexpected RequestID: got %d, expected %d", resp.RequestID, reqID)
		return nil, nil
	case <-time.After(5 * time.Second):
		c.log.Warningf("Timeout waiting for ParametersResponse from plugin %s", c.capability)
		return nil, nil
	case <-c.HaltCh():
		return nil, nil
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
	c.Go(c.reaper)
	c.socket.Start(true, c.socketFile, c.commandBuilder)
	return nil
}

func (c *Client) reaper() {
	<-c.HaltCh()
	err := c.process.Signal(syscall.SIGTERM)
	if err != nil {
		c.log.Errorf("CBOR plugin worker, error sending SIGTERM: %s\n", err)
	}
	err = c.process.Wait()
	if err != nil {
		c.log.Errorf("CBOR plugin worker, command exec error: %s\n", err)
	}
}

func (c *Client) logPluginStderr(stderr io.ReadCloser) {
	logWriter := c.logBackend.GetLogWriter(c.process.Path(), "DEBUG")
	_, err := io.Copy(logWriter, stderr)
	if err != nil {
		c.log.Errorf("Failed to proxy cborplugin stderr to DEBUG log: %s", err)
	}
	c.Halt()
}

func (c *Client) launch(command string, args []string) error {
	// exec plugin
	c.process = c.processFactory.NewProcess(command, args)
	stdout, err := c.process.StdoutPipe()
	if err != nil {
		c.log.Debugf("pipe failure: %s", err)
		return err
	}
	stderr, err := c.process.StderrPipe()
	if err != nil {
		c.log.Debugf("pipe failure: %s", err)
		return err
	}
	err = c.process.Start()
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

// ReadChan returns the channel for reading commands from the plugin.
// Note: ParametersResponse messages are filtered out and handled internally.
// This channel will only receive Response messages (plugin service responses).
func (c *Client) ReadChan() chan Command {
	return c.socket.ReadChan()
}

func (c *Client) WriteChan() chan Command {
	return c.socket.WriteChan()
}

// HandleMessage processes a ResponseMessage from the plugin, routing ParametersResponse
// internally and returning true. Returns false for other message types which
// should be handled by the caller.
func (c *Client) HandleMessage(cmd Command) bool {
	msg, ok := cmd.(*ResponseMessage)
	if !ok {
		return false
	}

	if msg.ParametersResponse != nil {
		select {
		case c.paramResponseCh <- msg.ParametersResponse:
		default:
			c.log.Warningf("ParametersResponse channel full, dropping response")
		}
		return true
	}

	return false
}
