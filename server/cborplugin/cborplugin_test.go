// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package cborplugin

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/stretchr/testify/require"
)

func newTestLogBackend(t *testing.T) *log.Backend {
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	return logBackend
}

// testSocketPath returns a temporary socket file path suitable for the current OS
func testSocketPath(name string) string {
	return filepath.Join(os.TempDir(), name+"_"+time.Now().Format("20060102150405")+".sock")
}

// MockLogger implements the Logger interface for testing
type MockLogger struct {
	fatalCalled bool
	fatalArgs   []interface{}
}

func (m *MockLogger) Debugf(format string, args ...interface{}) {}

func (m *MockLogger) Fatal(args ...interface{}) {
	m.fatalCalled = true
	m.fatalArgs = args
}

// =============================================================================
// Serialization Tests
// =============================================================================

func TestRequestMarshalUnmarshal(t *testing.T) {
	// Truncate to second because CBOR time encoding doesn't preserve sub-second precision
	req := &Request{
		RequestAt: time.Now().Truncate(time.Second),
		Delay:     5 * time.Second,
		ID:        12345,
		Payload:   []byte("test payload"),
		SURB:      []byte("test surb"),
	}

	data, err := req.Marshal()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	req2 := &Request{}
	err = req2.Unmarshal(data)
	require.NoError(t, err)
	require.Equal(t, req.RequestAt.UTC(), req2.RequestAt.UTC())
	require.Equal(t, req.Delay, req2.Delay)
	require.Equal(t, req.ID, req2.ID)
	require.Equal(t, req.Payload, req2.Payload)
	require.Equal(t, req.SURB, req2.SURB)
}

func TestResponseMarshalUnmarshal(t *testing.T) {
	// Truncate to second because CBOR time encoding doesn't preserve sub-second precision
	resp := &Response{
		RequestAt: time.Now().Truncate(time.Second),
		Delay:     10 * time.Second,
		ID:        67890,
		Payload:   []byte("response payload"),
		SURB:      []byte("response surb"),
	}

	data, err := resp.Marshal()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	resp2 := &Response{}
	err = resp2.Unmarshal(data)
	require.NoError(t, err)
	require.Equal(t, resp.RequestAt.UTC(), resp2.RequestAt.UTC())
	require.Equal(t, resp.Delay, resp2.Delay)
	require.Equal(t, resp.ID, resp2.ID)
	require.Equal(t, resp.Payload, resp2.Payload)
	require.Equal(t, resp.SURB, resp2.SURB)
}

func TestRequestMessageWithRequest(t *testing.T) {
	msg := &RequestMessage{
		Request: &Request{
			ID:      111,
			Payload: []byte("inner request"),
		},
	}

	data, err := msg.Marshal()
	require.NoError(t, err)

	msg2 := &RequestMessage{}
	err = msg2.Unmarshal(data)
	require.NoError(t, err)
	require.NotNil(t, msg2.Request)
	require.Nil(t, msg2.ParametersRequest)
	require.Equal(t, msg.Request.ID, msg2.Request.ID)
	require.Equal(t, msg.Request.Payload, msg2.Request.Payload)
}

func TestRequestMessageWithParametersRequest(t *testing.T) {
	msg := &RequestMessage{
		ParametersRequest: &ParametersRequest{
			RequestID: 999,
		},
	}

	data, err := msg.Marshal()
	require.NoError(t, err)

	msg2 := &RequestMessage{}
	err = msg2.Unmarshal(data)
	require.NoError(t, err)
	require.Nil(t, msg2.Request)
	require.NotNil(t, msg2.ParametersRequest)
	require.Equal(t, uint64(999), msg2.ParametersRequest.RequestID)
}

func TestResponseMessageWithResponse(t *testing.T) {
	msg := &ResponseMessage{
		Response: &Response{
			ID:      222,
			Payload: []byte("inner response"),
		},
	}

	data, err := msg.Marshal()
	require.NoError(t, err)

	msg2 := &ResponseMessage{}
	err = msg2.Unmarshal(data)
	require.NoError(t, err)
	require.NotNil(t, msg2.Response)
	require.Nil(t, msg2.ParametersResponse)
	require.Equal(t, msg.Response.ID, msg2.Response.ID)
}

func TestResponseMessageWithParametersResponse(t *testing.T) {
	params := Parameters{
		"key1": "value1",
		"key2": float64(42),
		"nested": map[string]interface{}{
			"inner": "data",
		},
	}
	msg := &ResponseMessage{
		ParametersResponse: &ParametersResponse{
			RequestID: 888,
			Params:    params,
		},
	}

	data, err := msg.Marshal()
	require.NoError(t, err)

	msg2 := &ResponseMessage{}
	err = msg2.Unmarshal(data)
	require.NoError(t, err)
	require.Nil(t, msg2.Response)
	require.NotNil(t, msg2.ParametersResponse)
	require.Equal(t, uint64(888), msg2.ParametersResponse.RequestID)
	require.Equal(t, "value1", msg2.ParametersResponse.Params["key1"])
}

// =============================================================================
// Factory Tests
// =============================================================================

func TestRequestMessageFactory(t *testing.T) {
	factory := &RequestMessageFactory{}
	cmd := factory.Build()
	require.NotNil(t, cmd)

	msg, ok := cmd.(*RequestMessage)
	require.True(t, ok)
	require.NotNil(t, msg)
	require.Nil(t, msg.Request)
	require.Nil(t, msg.ParametersRequest)
}

func TestResponseMessageFactory(t *testing.T) {
	factory := &ResponseMessageFactory{}
	cmd := factory.Build()
	require.NotNil(t, cmd)

	msg, ok := cmd.(*ResponseMessage)
	require.True(t, ok)
	require.NotNil(t, msg)
	require.Nil(t, msg.Response)
	require.Nil(t, msg.ParametersResponse)
}

// =============================================================================
// Mock Types for Testing
// =============================================================================

// MockConn implements net.Conn for testing
type MockConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	closed   bool
	mu       sync.Mutex
}

func NewMockConn() *MockConn {
	return &MockConn{
		readBuf:  &bytes.Buffer{},
		writeBuf: &bytes.Buffer{},
	}
}

func (c *MockConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.EOF
	}
	return c.readBuf.Read(b)
}

func (c *MockConn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errors.New("connection closed")
	}
	return c.writeBuf.Write(b)
}

func (c *MockConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *MockConn) LocalAddr() net.Addr                { return nil }
func (c *MockConn) RemoteAddr() net.Addr               { return nil }
func (c *MockConn) SetDeadline(t time.Time) error      { return nil }
func (c *MockConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *MockConn) SetWriteDeadline(t time.Time) error { return nil }

// MockListener implements net.Listener for testing
type MockListener struct {
	conn      net.Conn
	acceptErr error
	closed    bool
}

func (l *MockListener) Accept() (net.Conn, error) {
	if l.acceptErr != nil {
		return nil, l.acceptErr
	}
	return l.conn, nil
}

func (l *MockListener) Close() error {
	l.closed = true
	return nil
}

func (l *MockListener) Addr() net.Addr {
	return nil
}

// MockDialer implements Dialer for testing
type MockDialer struct {
	conn     net.Conn
	dialErr  error
	dialFunc func(network, address string) (net.Conn, error)
}

func (d *MockDialer) Dial(network, address string) (net.Conn, error) {
	if d.dialFunc != nil {
		return d.dialFunc(network, address)
	}
	if d.dialErr != nil {
		return nil, d.dialErr
	}
	return d.conn, nil
}

// MockListenerFactory implements ListenerFactory for testing
type MockListenerFactory struct {
	listener   net.Listener
	listenErr  error
	listenFunc func(network, address string) (net.Listener, error)
}

func (f *MockListenerFactory) Listen(network, address string) (net.Listener, error) {
	if f.listenFunc != nil {
		return f.listenFunc(network, address)
	}
	if f.listenErr != nil {
		return nil, f.listenErr
	}
	return f.listener, nil
}

// MockProcess implements Process for testing
type MockProcess struct {
	stdout    io.ReadCloser
	stderr    io.ReadCloser
	startErr  error
	waitErr   error
	signalErr error
	stdoutErr error
	stderrErr error
	path      string
	started   bool
	signaled  bool
	waited    bool
	mu        sync.Mutex
}

func (p *MockProcess) Signal(sig os.Signal) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.signaled = true
	return p.signalErr
}

func (p *MockProcess) Wait() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.waited = true
	return p.waitErr
}

func (p *MockProcess) IsSignaled() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.signaled
}

func (p *MockProcess) IsWaited() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.waited
}

func (p *MockProcess) StdoutPipe() (io.ReadCloser, error) {
	return p.stdout, p.stdoutErr
}

func (p *MockProcess) StderrPipe() (io.ReadCloser, error) {
	return p.stderr, p.stderrErr
}

func (p *MockProcess) Start() error {
	p.started = true
	return p.startErr
}

func (p *MockProcess) Path() string {
	return p.path
}

// MockProcessFactory implements ProcessFactory for testing
type MockProcessFactory struct {
	process *MockProcess
}

func (f *MockProcessFactory) NewProcess(command string, args []string) Process {
	return f.process
}

// MockServerPlugin implements ServerPlugin for testing
type MockServerPlugin struct {
	onCommandErr    error
	onCommandCalls  []Command
	params          Parameters
	server          *Server
	registered      bool
	commandReceived bool
}

func (p *MockServerPlugin) OnCommand(cmd Command) error {
	p.onCommandCalls = append(p.onCommandCalls, cmd)
	p.commandReceived = true
	return p.onCommandErr
}

func (p *MockServerPlugin) RegisterConsumer(s *Server) {
	p.server = s
	p.registered = true
}

func (p *MockServerPlugin) GetParameters() Parameters {
	return p.params
}

// MockReadCloser for stdout/stderr pipes
type MockReadCloser struct {
	buf     *bytes.Buffer
	closed  bool
	readErr error
}

func NewMockReadCloser(data string) *MockReadCloser {
	return &MockReadCloser{buf: bytes.NewBufferString(data)}
}

func NewMockReadCloserWithError(err error) *MockReadCloser {
	return &MockReadCloser{buf: bytes.NewBufferString(""), readErr: err}
}

func (r *MockReadCloser) Read(p []byte) (n int, err error) {
	if r.readErr != nil {
		return 0, r.readErr
	}
	return r.buf.Read(p)
}

func (r *MockReadCloser) Close() error {
	r.closed = true
	return nil
}

// =============================================================================
// NetDialer and NetListenerFactory Tests
// =============================================================================

func TestNetDialer(t *testing.T) {
	dialer := &NetDialer{}
	// Dial to non-existent address should fail
	_, err := dialer.Dial("unix", "/nonexistent/socket/path")
	require.Error(t, err)
}

func TestNetListenerFactory(t *testing.T) {
	factory := &NetListenerFactory{}
	// Create a temp file path for the socket
	tmpDir := t.TempDir()
	socketPath := tmpDir + "/test.sock"

	listener, err := factory.Listen("unix", socketPath)
	require.NoError(t, err)
	require.NotNil(t, listener)
	listener.Close()
}

// =============================================================================
// CommandIO Tests
// =============================================================================

func TestNewCommandIO(t *testing.T) {
	// Create a mock logger
	cmdIO := NewCommandIO(nil)
	require.NotNil(t, cmdIO)
	require.NotNil(t, cmdIO.readCh)
	require.NotNil(t, cmdIO.writeCh)
	require.NotNil(t, cmdIO.dialer)
	require.NotNil(t, cmdIO.listenerFactory)
}

func TestNewCommandIOWithDeps(t *testing.T) {
	mockDialer := &MockDialer{}
	mockFactory := &MockListenerFactory{}

	cmdIO := NewCommandIOWithDeps(nil, mockDialer, mockFactory)
	require.NotNil(t, cmdIO)
	require.Equal(t, mockDialer, cmdIO.dialer)
	require.Equal(t, mockFactory, cmdIO.listenerFactory)
}

func TestCommandIOReadWriteChans(t *testing.T) {
	cmdIO := NewCommandIO(nil)
	require.Equal(t, cmdIO.readCh, cmdIO.ReadChan())
	require.Equal(t, cmdIO.writeCh, cmdIO.WriteChan())
}

// =============================================================================
// Client Tests
// =============================================================================

func TestNewClient(t *testing.T) {
	client := NewClient(nil, "echo", "+echo", new(RequestMessageFactory))
	require.NotNil(t, client)
	require.Equal(t, "echo", client.Capability())
	require.NotNil(t, client.socket)
	require.NotNil(t, client.processFactory)
}

func TestClientGetParametersReturnsEndpoint(t *testing.T) {
	client := NewClient(nil, "echo", "+echo", new(RequestMessageFactory))
	params := client.GetParameters()
	require.NotNil(t, params)
	require.Equal(t, "+echo", (*params)["endpoint"])
	require.Len(t, *params, 1) // Only endpoint
}

func TestClientRequestParametersSuccess(t *testing.T) {
	logBackend := newTestLogBackend(t)
	client := NewClient(logBackend, "echo", "+echo", new(RequestMessageFactory))

	// Consume from write channel and send response with dynamic params
	go func() {
		<-client.WriteChan()
		client.paramResponseCh <- &ParametersResponse{
			RequestID: 1,
			Params:    Parameters{"dynamic_key": "dynamic_value"},
		}
	}()

	params := client.RequestParameters()
	require.NotNil(t, params)
	require.Equal(t, "dynamic_value", params["dynamic_key"])
}

func TestClientRequestParametersNil(t *testing.T) {
	logBackend := newTestLogBackend(t)
	client := NewClient(logBackend, "echo", "+echo", new(RequestMessageFactory))

	// Consume from write channel and send response with nil params
	go func() {
		<-client.WriteChan()
		client.paramResponseCh <- &ParametersResponse{
			RequestID: 1,
			Params:    nil,
		}
	}()

	params := client.RequestParameters()
	require.Nil(t, params)
}

// =============================================================================
// HandleMessage Tests
// =============================================================================

func TestHandleMessageWithResponse(t *testing.T) {
	client := NewClient(nil, "echo", "+echo", new(RequestMessageFactory))

	// ResponseMessage with Response field set - not handled by HandleMessage
	// because HandleMessage only handles ParametersResponse
	respMsg := &ResponseMessage{
		Response: &Response{
			ID:      123,
			Payload: []byte("response data"),
		},
	}

	handled := client.HandleMessage(respMsg)
	require.False(t, handled) // Response is not handled internally
}

func TestHandleMessageWithParametersResponse(t *testing.T) {
	client := NewClient(nil, "echo", "+echo", new(RequestMessageFactory))

	paramResp := &ResponseMessage{
		ParametersResponse: &ParametersResponse{
			RequestID: 999,
			Params: Parameters{
				"key": "value",
			},
		},
	}

	handled := client.HandleMessage(paramResp)
	require.True(t, handled) // ParametersResponse is handled internally

	// Check that paramResponseCh received the response
	select {
	case resp := <-client.paramResponseCh:
		require.Equal(t, uint64(999), resp.RequestID)
		require.Equal(t, "value", resp.Params["key"])
	default:
		t.Fatal("expected ParametersResponse on channel")
	}
}

func TestHandleMessageWithEmptyResponseMessage(t *testing.T) {
	client := NewClient(nil, "echo", "+echo", new(RequestMessageFactory))

	emptyResp := &ResponseMessage{}

	handled := client.HandleMessage(emptyResp)
	require.False(t, handled)
}

func TestHandleMessageWithNonResponseMessage(t *testing.T) {
	client := NewClient(nil, "echo", "+echo", new(RequestMessageFactory))

	// Pass a Request instead of ResponseMessage
	req := &Request{ID: 123}

	handled := client.HandleMessage(req)
	require.False(t, handled)
}

// =============================================================================
// ParametersRequest/Response via RequestMessage/ResponseMessage Tests
// =============================================================================

func TestParametersRequestViaRequestMessage(t *testing.T) {
	msg := &RequestMessage{
		ParametersRequest: &ParametersRequest{
			RequestID: 12345,
		},
	}

	data, err := msg.Marshal()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	msg2 := &RequestMessage{}
	err = msg2.Unmarshal(data)
	require.NoError(t, err)
	require.NotNil(t, msg2.ParametersRequest)
	require.Equal(t, uint64(12345), msg2.ParametersRequest.RequestID)
}

func TestParametersResponseViaResponseMessage(t *testing.T) {
	msg := &ResponseMessage{
		ParametersResponse: &ParametersResponse{
			RequestID: 67890,
			Params: Parameters{
				"string_val": "hello",
				"int_val":    float64(42), // CBOR decodes numbers as float64
				"bool_val":   true,
				"array_val":  []interface{}{"a", "b", "c"},
				"nested_map": map[string]interface{}{"inner": "value"},
			},
		},
	}

	data, err := msg.Marshal()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	msg2 := &ResponseMessage{}
	err = msg2.Unmarshal(data)
	require.NoError(t, err)
	require.NotNil(t, msg2.ParametersResponse)
	require.Equal(t, uint64(67890), msg2.ParametersResponse.RequestID)
	require.Equal(t, "hello", msg2.ParametersResponse.Params["string_val"])
	require.Equal(t, float64(42), msg2.ParametersResponse.Params["int_val"])
	require.Equal(t, true, msg2.ParametersResponse.Params["bool_val"])
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestRequestWithEmptyFields(t *testing.T) {
	req := &Request{}

	data, err := req.Marshal()
	require.NoError(t, err)

	req2 := &Request{}
	err = req2.Unmarshal(data)
	require.NoError(t, err)
	require.Empty(t, req2.Payload)
	require.Empty(t, req2.SURB)
}

func TestResponseWithEmptyFields(t *testing.T) {
	resp := &Response{}

	data, err := resp.Marshal()
	require.NoError(t, err)

	resp2 := &Response{}
	err = resp2.Unmarshal(data)
	require.NoError(t, err)
	require.Empty(t, resp2.Payload)
	require.Empty(t, resp2.SURB)
}

func TestRequestWithLargePayload(t *testing.T) {
	// Test with a large payload (64KB)
	largePayload := make([]byte, 64*1024)
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}

	req := &Request{
		ID:      999,
		Payload: largePayload,
	}

	data, err := req.Marshal()
	require.NoError(t, err)

	req2 := &Request{}
	err = req2.Unmarshal(data)
	require.NoError(t, err)
	require.Equal(t, largePayload, req2.Payload)
}

func TestParametersWithNilParams(t *testing.T) {
	msg := &ResponseMessage{
		ParametersResponse: &ParametersResponse{
			RequestID: 123,
			Params:    nil,
		},
	}

	data, err := msg.Marshal()
	require.NoError(t, err)

	msg2 := &ResponseMessage{}
	err = msg2.Unmarshal(data)
	require.NoError(t, err)
	require.NotNil(t, msg2.ParametersResponse)
	require.Equal(t, uint64(123), msg2.ParametersResponse.RequestID)
}

func TestRequestMessageWithBothFieldsNil(t *testing.T) {
	msg := &RequestMessage{}

	data, err := msg.Marshal()
	require.NoError(t, err)

	msg2 := &RequestMessage{}
	err = msg2.Unmarshal(data)
	require.NoError(t, err)
	require.Nil(t, msg2.Request)
	require.Nil(t, msg2.ParametersRequest)
}

func TestResponseMessageWithBothFieldsNil(t *testing.T) {
	msg := &ResponseMessage{}

	data, err := msg.Marshal()
	require.NoError(t, err)

	msg2 := &ResponseMessage{}
	err = msg2.Unmarshal(data)
	require.NoError(t, err)
	require.Nil(t, msg2.Response)
	require.Nil(t, msg2.ParametersResponse)
}

// =============================================================================
// Client Launch/Start/Reaper Tests
// =============================================================================

func TestClientLaunch(t *testing.T) {
	logBackend := newTestLogBackend(t)
	client := NewClient(logBackend, "test", "+test", new(RequestMessageFactory))

	// Create mock stdout that returns a socket path
	mockStdout := NewMockReadCloser("/tmp/test.sock\n")
	mockStderr := NewMockReadCloser("")

	mockProcess := &MockProcess{
		stdout: mockStdout,
		stderr: mockStderr,
		path:   "/path/to/plugin",
	}
	client.processFactory = &MockProcessFactory{process: mockProcess}

	err := client.launch("plugin", []string{"arg1"})
	require.NoError(t, err)
	require.True(t, mockProcess.started)
	require.Equal(t, "/tmp/test.sock", client.socketFile)
}

func TestClientLaunchStartError(t *testing.T) {
	logBackend := newTestLogBackend(t)
	client := NewClient(logBackend, "test", "+test", new(RequestMessageFactory))

	mockStdout := NewMockReadCloser("")
	mockStderr := NewMockReadCloser("")

	mockProcess := &MockProcess{
		stdout:   mockStdout,
		stderr:   mockStderr,
		startErr: errors.New("start failed"),
	}
	client.processFactory = &MockProcessFactory{process: mockProcess}

	err := client.launch("plugin", []string{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "start failed")
}

func TestClientLaunchStdoutPipeError(t *testing.T) {
	logBackend := newTestLogBackend(t)
	client := NewClient(logBackend, "test", "+test", new(RequestMessageFactory))

	mockProcess := &MockProcess{
		stdoutErr: errors.New("stdout pipe failed"),
	}
	client.processFactory = &MockProcessFactory{process: mockProcess}

	err := client.launch("plugin", []string{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "stdout pipe failed")
}

func TestClientLaunchStderrPipeError(t *testing.T) {
	logBackend := newTestLogBackend(t)
	client := NewClient(logBackend, "test", "+test", new(RequestMessageFactory))

	mockStdout := NewMockReadCloser("")
	mockProcess := &MockProcess{
		stdout:    mockStdout,
		stderrErr: errors.New("stderr pipe failed"),
	}
	client.processFactory = &MockProcessFactory{process: mockProcess}

	err := client.launch("plugin", []string{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "stderr pipe failed")
}

func TestClientReaper(t *testing.T) {
	logBackend := newTestLogBackend(t)
	client := NewClient(logBackend, "test", "+test", new(RequestMessageFactory))

	mockProcess := &MockProcess{}
	client.process = mockProcess

	// Start the reaper in a goroutine
	go client.reaper()

	// Signal halt
	client.Halt()

	// Wait a bit for reaper to process
	time.Sleep(50 * time.Millisecond)

	require.True(t, mockProcess.IsSignaled())
	require.True(t, mockProcess.IsWaited())
}

func TestClientReaperSignalError(t *testing.T) {
	logBackend := newTestLogBackend(t)
	client := NewClient(logBackend, "test", "+test", new(RequestMessageFactory))

	mockProcess := &MockProcess{
		signalErr: errors.New("signal failed"),
	}
	client.process = mockProcess

	go client.reaper()

	client.Halt()

	time.Sleep(50 * time.Millisecond)

	require.True(t, mockProcess.IsSignaled())
	require.True(t, mockProcess.IsWaited())
}

func TestClientReaperWaitError(t *testing.T) {
	logBackend := newTestLogBackend(t)
	client := NewClient(logBackend, "test", "+test", new(RequestMessageFactory))

	mockProcess := &MockProcess{
		waitErr: errors.New("wait failed"),
	}
	client.process = mockProcess

	go client.reaper()

	client.Halt()

	time.Sleep(50 * time.Millisecond)

	require.True(t, mockProcess.IsSignaled())
	require.True(t, mockProcess.IsWaited())
}

func TestClientLogPluginStderr(t *testing.T) {
	logBackend := newTestLogBackend(t)
	client := NewClient(logBackend, "test", "+test", new(RequestMessageFactory))

	mockProcess := &MockProcess{path: "/path/to/plugin"}
	client.process = mockProcess

	mockStderr := NewMockReadCloser("some stderr output")

	// logPluginStderr will call Halt() when stderr closes
	go func() {
		client.logPluginStderr(mockStderr)
	}()

	// Wait for Halt to be called
	select {
	case <-client.HaltCh():
		// Success - Halt was called
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected Halt to be called")
	}
}

func TestClientLogPluginStderrReadError(t *testing.T) {
	logBackend := newTestLogBackend(t)
	client := NewClient(logBackend, "test", "+test", new(RequestMessageFactory))

	mockProcess := &MockProcess{path: "/path/to/plugin"}
	client.process = mockProcess

	mockStderr := NewMockReadCloserWithError(errors.New("read error"))

	// logPluginStderr will call Halt() even on error
	go func() {
		client.logPluginStderr(mockStderr)
	}()

	// Wait for Halt to be called
	select {
	case <-client.HaltCh():
		// Success - Halt was called
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected Halt to be called")
	}
}

func TestClientReadWriteChan(t *testing.T) {
	logBackend := newTestLogBackend(t)
	client := NewClient(logBackend, "test", "+test", new(RequestMessageFactory))

	// ReadChan and WriteChan should return the socket's channels
	require.NotNil(t, client.ReadChan())
	require.NotNil(t, client.WriteChan())
}

func TestClientStart(t *testing.T) {
	logBackend := newTestLogBackend(t)
	client := NewClient(logBackend, "test", "+test", new(RequestMessageFactory))

	// Create mock stdout that returns a socket path
	mockStdout := NewMockReadCloser("/tmp/test.sock\n")
	mockStderr := NewMockReadCloser("")

	mockProcess := &MockProcess{
		stdout: mockStdout,
		stderr: mockStderr,
		path:   "/path/to/plugin",
	}
	client.processFactory = &MockProcessFactory{process: mockProcess}

	// Inject mock dialer into socket - pre-close it so reader exits immediately
	mockConn := NewMockConn()
	mockConn.Close() // Close so reader goroutine exits immediately
	client.socket.dialer = &MockDialer{conn: mockConn}

	err := client.Start("plugin", []string{"arg1"})
	require.NoError(t, err)
	require.True(t, mockProcess.started)

	// Wait for goroutines to finish
	time.Sleep(100 * time.Millisecond)
}

func TestClientStartLaunchError(t *testing.T) {
	logBackend := newTestLogBackend(t)
	client := NewClient(logBackend, "test", "+test", new(RequestMessageFactory))

	mockProcess := &MockProcess{
		startErr: errors.New("launch failed"),
	}
	client.processFactory = &MockProcessFactory{process: mockProcess}

	err := client.Start("plugin", []string{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "launch failed")
}

// =============================================================================
// Client HandleMessage Warning Path Test
// =============================================================================

func TestHandleMessageChannelFull(t *testing.T) {
	logBackend := newTestLogBackend(t)
	client := NewClient(logBackend, "test", "+test", new(RequestMessageFactory))

	// Fill the channel (capacity is 1)
	client.paramResponseCh <- &ParametersResponse{RequestID: 1}

	// Now send another - should trigger warning path
	paramResp := &ResponseMessage{
		ParametersResponse: &ParametersResponse{
			RequestID: 2,
			Params:    Parameters{"key": "value"},
		},
	}

	// This should return true but drop the message (warning logged)
	handled := client.HandleMessage(paramResp)
	require.True(t, handled)

	// Channel should still have the first message
	resp := <-client.paramResponseCh
	require.Equal(t, uint64(1), resp.RequestID)
}

// =============================================================================
// Client GetParameters Tests (with plugin communication)
// =============================================================================

func TestClientRequestParametersHalt(t *testing.T) {
	logBackend := newTestLogBackend(t)
	client := NewClient(logBackend, "test", "+test", new(RequestMessageFactory))

	// Consume from write channel and halt
	go func() {
		<-client.WriteChan()
		client.Halt()
	}()

	params := client.RequestParameters()
	require.Nil(t, params)
}

func TestClientRequestParametersTimeout(t *testing.T) {
	logBackend := newTestLogBackend(t)
	client := NewClient(logBackend, "test", "+test", new(RequestMessageFactory))

	// Consume from write channel but don't send a response - let it timeout
	go func() {
		<-client.WriteChan()
		// Don't send anything - let the 5 second timeout occur
	}()

	start := time.Now()
	params := client.RequestParameters()
	elapsed := time.Since(start)

	require.Nil(t, params)
	// Should have taken at least 5 seconds (the timeout)
	require.GreaterOrEqual(t, elapsed, 5*time.Second)
}

// =============================================================================
// CommandIO Start/Accept Tests
// =============================================================================

func TestCommandIOStartNonInitiator(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	// Create a temp socket file
	socketFile := testSocketPath("test_cborplugin")
	defer os.Remove(socketFile)

	mockListener := &MockListener{
		conn: NewMockConn(),
	}
	mockListenerFactory := &MockListenerFactory{listener: mockListener}

	cio := NewCommandIOWithDeps(log, &MockDialer{}, mockListenerFactory)
	cio.Start(false, socketFile, new(ResponseMessageFactory))

	// Should have created a listener
	require.NotNil(t, cio.listener)
}

func TestCommandIOStartNonInitiatorRetry(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	socketFile := testSocketPath("test_cborplugin_retry")
	defer os.Remove(socketFile)

	// First Listen fails, second succeeds (simulating stale socket file)
	callCount := 0
	mockListenerFactory := &MockListenerFactory{
		listenFunc: func(network, address string) (net.Listener, error) {
			callCount++
			if callCount == 1 {
				return nil, errors.New("address already in use")
			}
			return &MockListener{conn: NewMockConn()}, nil
		},
	}

	cio := NewCommandIOWithDeps(log, &MockDialer{}, mockListenerFactory)
	cio.Start(false, socketFile, new(ResponseMessageFactory))

	require.Equal(t, 2, callCount)
	require.NotNil(t, cio.listener)
}

func TestCommandIOAccept(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	mockConn := NewMockConn()
	mockConn.Close() // Close so reader exits immediately
	mockListener := &MockListener{conn: mockConn}

	cio := NewCommandIOWithDeps(log, &MockDialer{}, &MockListenerFactory{listener: mockListener})
	cio.listener = mockListener
	cio.commandBuilder = new(ResponseMessageFactory)

	cio.Accept()

	// Connection should be set
	require.NotNil(t, cio.conn)

	// Wait for goroutines to start and halt
	time.Sleep(50 * time.Millisecond)
}

func TestCommandIOReaderWriterIntegration(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	// Create a pipe to simulate connection
	serverConn, clientConn := net.Pipe()

	// Server side CommandIO
	serverIO := NewCommandIOWithDeps(log, &MockDialer{}, &MockListenerFactory{})
	serverIO.conn = serverConn
	serverIO.commandBuilder = new(ResponseMessageFactory)
	serverIO.Go(serverIO.reader)
	serverIO.Go(serverIO.writer)

	// Client side CommandIO
	clientIO := NewCommandIOWithDeps(log, &MockDialer{}, &MockListenerFactory{})
	clientIO.conn = clientConn
	clientIO.commandBuilder = new(RequestMessageFactory)
	clientIO.Go(clientIO.reader)
	clientIO.Go(clientIO.writer)

	// Send a request from client to server
	req := &RequestMessage{
		Request: &Request{
			ID:      123,
			Payload: []byte("hello"),
		},
	}
	clientIO.WriteChan() <- req

	// Read on server
	select {
	case cmd := <-serverIO.ReadChan():
		msg, ok := cmd.(*ResponseMessage)
		require.True(t, ok)
		// ResponseMessageFactory builds ResponseMessage, but we sent RequestMessage
		// The decoding should still work since it's CBOR
		_ = msg
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for message")
	}

	// Close connections first to unblock readers, then Halt
	serverConn.Close()
	clientConn.Close()
	time.Sleep(50 * time.Millisecond)
}

func TestCommandIOWriterEncodeError(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	mockConn := NewMockConn()
	mockConn.Close() // Close connection so writes fail

	cio := NewCommandIOWithDeps(log, &MockDialer{}, &MockListenerFactory{})
	cio.conn = mockConn
	cio.Go(cio.writer)

	// Send a message - should fail to encode and halt
	cio.WriteChan() <- &ResponseMessage{}

	// Wait for halt
	select {
	case <-cio.HaltCh():
		// Success
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected halt after encode error")
	}
}

// =============================================================================
// Server Tests
// =============================================================================

func TestNewServer(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	socketFile := testSocketPath("test_server")
	defer os.Remove(socketFile)

	mockPlugin := &MockServerPlugin{
		params: Parameters{"key": "value"},
	}

	server := NewServer(log, socketFile, new(RequestMessageFactory), mockPlugin)
	require.NotNil(t, server)
	require.True(t, mockPlugin.registered)

	// Cleanup
	server.Halt()
}

func TestServerHandleCommandLegacy(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	socketFile := testSocketPath("test_server_legacy")
	defer os.Remove(socketFile)

	mockPlugin := &MockServerPlugin{}

	server := NewServer(log, socketFile, new(RequestMessageFactory), mockPlugin)

	// Send a legacy Request command
	req := &Request{
		ID:      1,
		Payload: []byte("test"),
	}
	server.handleCommand(req)

	require.True(t, mockPlugin.commandReceived)

	server.Halt()
}

func TestServerHandleRequestMessageWithRequest(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	socketFile := testSocketPath("test_server_req")
	defer os.Remove(socketFile)

	mockPlugin := &MockServerPlugin{}

	server := NewServer(log, socketFile, new(RequestMessageFactory), mockPlugin)

	// Send a RequestMessage with Request
	msg := &RequestMessage{
		Request: &Request{
			ID:      1,
			Payload: []byte("test"),
		},
	}
	server.handleCommand(msg)

	require.True(t, mockPlugin.commandReceived)

	server.Halt()
}

func TestServerHandleRequestMessageWithParametersRequest(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	socketFile := testSocketPath("test_server_params")
	defer os.Remove(socketFile)

	mockPlugin := &MockServerPlugin{
		params: Parameters{"dynamic": "value"},
	}

	server := NewServer(log, socketFile, new(RequestMessageFactory), mockPlugin)

	// Consume response in goroutine
	done := make(chan bool)
	go func() {
		select {
		case <-server.socket.WriteChan():
			done <- true
		case <-time.After(100 * time.Millisecond):
			done <- false
		}
	}()

	// Send a RequestMessage with ParametersRequest
	msg := &RequestMessage{
		ParametersRequest: &ParametersRequest{
			RequestID: 42,
		},
	}
	server.handleRequestMessage(msg)

	require.True(t, <-done)

	server.Halt()
}

func TestServerHandleRequestMessageEmpty(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	socketFile := testSocketPath("test_server_empty")
	defer os.Remove(socketFile)

	mockPlugin := &MockServerPlugin{}

	server := NewServer(log, socketFile, new(RequestMessageFactory), mockPlugin)

	// Send empty RequestMessage - should just log
	msg := &RequestMessage{}
	server.handleRequestMessage(msg)

	// Plugin should not have received any command
	require.False(t, mockPlugin.commandReceived)

	server.Halt()
}

func TestServerWrite(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	socketFile := testSocketPath("test_server_write")
	defer os.Remove(socketFile)

	mockPlugin := &MockServerPlugin{}

	server := NewServer(log, socketFile, new(RequestMessageFactory), mockPlugin)

	// Consume in goroutine
	done := make(chan bool)
	go func() {
		select {
		case cmd := <-server.socket.WriteChan():
			if _, ok := cmd.(*ResponseMessage); ok {
				done <- true
			} else {
				done <- false
			}
		case <-time.After(100 * time.Millisecond):
			done <- false
		}
	}()

	resp := &ResponseMessage{
		Response: &Response{
			ID:      1,
			Payload: []byte("response"),
		},
	}
	server.Write(resp)

	require.True(t, <-done)

	server.Halt()
}

func TestServerAcceptAndWorker(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	socketFile := testSocketPath("test_server_worker")
	defer os.Remove(socketFile)

	mockPlugin := &MockServerPlugin{
		params: Parameters{"key": "value"},
	}

	server := NewServer(log, socketFile, new(RequestMessageFactory), mockPlugin)

	// Use a channel to signal when Accept has been called
	acceptDone := make(chan struct{})

	// Accept connection and run worker in goroutine
	go func() {
		server.Accept()
		close(acceptDone)
	}()

	// Wait for Accept to start (give it time to call Go())
	time.Sleep(50 * time.Millisecond)

	// Create a client connection
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		conn, err := net.Dial("unix", socketFile)
		if err != nil {
			return
		}
		defer conn.Close()

		// Send a RequestMessage with ParametersRequest
		enc := cbor.NewEncoder(conn)
		msg := &RequestMessage{
			ParametersRequest: &ParametersRequest{RequestID: 1},
		}
		enc.Encode(msg)

		// Read response
		dec := cbor.NewDecoder(conn)
		var resp ResponseMessage
		dec.Decode(&resp)
	}()

	// Wait for client to finish
	<-clientDone

	// Wait a bit for server to process
	time.Sleep(50 * time.Millisecond)

	// Halt the server
	server.Halt()

	// Wait for accept goroutine to finish
	<-acceptDone
}

func TestCommandIOReaderHaltDuringWrite(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	serverConn, clientConn := net.Pipe()

	cio := NewCommandIOWithDeps(log, &MockDialer{}, &MockListenerFactory{})
	cio.conn = serverConn
	cio.commandBuilder = new(ResponseMessageFactory)
	cio.Go(cio.reader)

	// Wait for reader to start, then close connections and halt
	time.Sleep(50 * time.Millisecond)
	clientConn.Close()
	serverConn.Close()
	// Reader should exit after connection is closed
	time.Sleep(50 * time.Millisecond)
}

func TestServerWorkerHaltPath(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	socketFile := testSocketPath("test_server_halt")
	defer os.Remove(socketFile)

	mockPlugin := &MockServerPlugin{}

	server := NewServer(log, socketFile, new(RequestMessageFactory), mockPlugin)

	// Start worker manually
	go server.worker()

	// Halt immediately
	time.Sleep(10 * time.Millisecond)
	server.Halt()
}

func TestServerWriteHaltPath(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	socketFile := testSocketPath("test_server_write_halt")
	defer os.Remove(socketFile)

	mockPlugin := &MockServerPlugin{}

	server := NewServer(log, socketFile, new(RequestMessageFactory), mockPlugin)

	// Halt the server first
	server.Halt()

	// Try to write after halt - should return immediately
	resp := &ResponseMessage{
		Response: &Response{ID: 1, Payload: []byte("test")},
	}
	server.Write(resp) // This should not block
}

func TestServerHandleCommandLegacyWithError(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	socketFile := testSocketPath("test_server_legacy_err")
	defer os.Remove(socketFile)

	mockPlugin := &MockServerPlugin{
		onCommandErr: errors.New("plugin error"),
	}

	server := NewServer(log, socketFile, new(RequestMessageFactory), mockPlugin)

	// Send a legacy Request command - should log error
	req := &Request{
		ID:      1,
		Payload: []byte("test"),
	}
	server.handleCommand(req)

	require.True(t, mockPlugin.commandReceived)

	server.Halt()
}

func TestServerHandleRequestMessageWithRequestError(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	socketFile := testSocketPath("test_server_req_err")
	defer os.Remove(socketFile)

	mockPlugin := &MockServerPlugin{
		onCommandErr: errors.New("plugin error"),
	}

	server := NewServer(log, socketFile, new(RequestMessageFactory), mockPlugin)

	// Send a RequestMessage with Request - should log error
	msg := &RequestMessage{
		Request: &Request{
			ID:      1,
			Payload: []byte("test"),
		},
	}
	server.handleRequestMessage(msg)

	require.True(t, mockPlugin.commandReceived)

	server.Halt()
}

func TestCommandIOStartInitiatorSuccess(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	mockConn := NewMockConn()
	mockConn.Close() // Close so reader/writer exit quickly

	mockDialer := &MockDialer{conn: mockConn}

	cio := NewCommandIOWithDeps(log, mockDialer, &MockListenerFactory{})
	cio.Start(true, "/tmp/test.sock", new(ResponseMessageFactory))

	// Should have connected
	require.NotNil(t, cio.conn)

	time.Sleep(50 * time.Millisecond)
}

func TestCommandIOStartInitiatorRetryThenSuccess(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	mockConn := NewMockConn()
	mockConn.Close()

	// First few dials fail, then succeed
	dialCount := 0
	mockDialer := &MockDialer{
		dialFunc: func(network, address string) (net.Conn, error) {
			dialCount++
			if dialCount < 3 {
				return nil, errors.New("connection refused")
			}
			return mockConn, nil
		},
	}

	cio := NewCommandIOWithDeps(log, mockDialer, &MockListenerFactory{})

	// Run in goroutine since it has sleeps
	done := make(chan bool)
	go func() {
		cio.Start(true, "/tmp/test.sock", new(ResponseMessageFactory))
		done <- true
	}()

	select {
	case <-done:
		require.Equal(t, 3, dialCount)
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for Start")
	}
}

func TestCommandIOReaderHaltWhileBlocked(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	serverConn, clientConn := net.Pipe()

	cio := NewCommandIOWithDeps(log, &MockDialer{}, &MockListenerFactory{})
	cio.conn = serverConn
	cio.commandBuilder = new(ResponseMessageFactory)

	// Start the reader
	cio.Go(cio.reader)

	// Send a valid CBOR message from client side
	enc := cbor.NewEncoder(clientConn)
	enc.Encode(&ResponseMessage{Response: &Response{ID: 1}})

	// Don't read from readCh - let it block
	// Then halt
	time.Sleep(50 * time.Millisecond)

	// Close connections to unblock the reader
	go func() {
		time.Sleep(50 * time.Millisecond)
		clientConn.Close()
		serverConn.Close()
	}()

	// Halt - reader should exit via HaltCh case
	cio.Halt()
}

func TestCommandIODialSuccess(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	mockConn := NewMockConn()
	mockDialer := &MockDialer{conn: mockConn}

	cio := NewCommandIOWithDeps(log, mockDialer, &MockListenerFactory{})

	err := cio.dial("/tmp/test.sock")
	require.NoError(t, err)
	require.NotNil(t, cio.conn)
}

// TestCommandIOStartInitiatorPanic tests the panic path when all dial attempts fail.
func TestCommandIOStartInitiatorPanic(t *testing.T) {
	logBackend := newTestLogBackend(t)
	log := logBackend.GetLogger("test")

	dialCount := 0
	mockDialer := &MockDialer{
		dialFunc: func(network, address string) (net.Conn, error) {
			dialCount++
			return nil, errors.New("connection refused")
		},
	}

	cio := NewCommandIOWithDeps(log, mockDialer, &MockListenerFactory{})
	cio.retryDelay = time.Millisecond // Fast retries for testing

	defer func() {
		if r := recover(); r != nil {
			// Expected panic after 40 retries
			require.Equal(t, 40, dialCount)
		} else {
			t.Fatal("expected panic but none occurred")
		}
	}()

	cio.Start(true, "/tmp/test.sock", new(ResponseMessageFactory))
}

// TestCommandIOStartNonInitiatorListenFatalBothFail tests the log.Fatal path when both Listen attempts fail
func TestCommandIOStartNonInitiatorListenFatalBothFail(t *testing.T) {
	mockLogger := &MockLogger{}

	callCount := 0
	mockListenerFactory := &MockListenerFactory{
		listenFunc: func(network, address string) (net.Listener, error) {
			callCount++
			return nil, errors.New("listen failed")
		},
	}

	cio := NewCommandIOWithDeps(mockLogger, &MockDialer{}, mockListenerFactory)

	cio.Start(false, "/tmp/test.sock", new(ResponseMessageFactory))

	require.True(t, mockLogger.fatalCalled)
	require.Equal(t, 2, callCount) // First attempt + retry after os.Remove
}

// TestCommandIOAcceptFatal tests the log.Fatal path when Accept fails
func TestCommandIOAcceptFatal(t *testing.T) {
	mockLogger := &MockLogger{}

	mockListener := &MockListener{
		acceptErr: errors.New("accept failed"),
	}

	cio := NewCommandIOWithDeps(mockLogger, &MockDialer{}, &MockListenerFactory{})
	cio.listener = mockListener
	cio.commandBuilder = new(ResponseMessageFactory)

	cio.Accept()

	require.True(t, mockLogger.fatalCalled)
}
