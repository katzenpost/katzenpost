package cborplugin

import (
	"bytes"
	"io/ioutil"
	"path/filepath"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/katzenpost/core/log"
)

type Payload struct {
	Payload []byte
}

func (p *Payload) Marshal() ([]byte, error) {
	return cbor.Marshal(p)
}

func (p *Payload) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, p)
}

func (p Payload) String() string {
	return string(p.Payload)
}

func TestPayload(t *testing.T) {
	p := &Payload{
		Payload: []byte("hello"),
	}
	s, err := p.Marshal()
	require.NoError(t, err)

	q := &Payload{
		Payload: []byte{},
	}
	err = q.Unmarshal(s)
	require.NoError(t, err)
}

type payloadFactory struct{}

func (p *payloadFactory) Build() Command {
	return new(Payload)
}

type Echo struct{}

func (e *Echo) OnCommand(cmd Command) (Command, error) {
	return cmd, nil
}

func (e *Echo) RegisterConsumer(s *Server) {
	// noop
}

func TestEchoService(t *testing.T) {
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	serverLog := logBackend.GetLogger("server")
	clientLog := logBackend.GetLogger("client")

	dir, err := ioutil.TempDir("", "echo_test")
	require.NoError(t, err)
	socketFile := filepath.Join(dir, "socket")

	commandFactory := new(payloadFactory)
	echo := new(Echo)

	var server *Server
	g := new(errgroup.Group)
	g.Go(func() error {
		server = NewServer(serverLog, socketFile, commandFactory, echo)
		return nil
	})
	err = g.Wait()
	require.NoError(t, err)

	client := NewCommandIO(clientLog)
	go client.Start(true, socketFile, commandFactory)
	server.Accept()

	hello := new(Payload)
	hello.Payload = []byte("hello")

	var reply Command
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		reply = <-client.ReadChan()
	}()

	client.WriteChan() <- hello
	wg.Wait()
	require.NotNil(t, reply)

	q := reply.(*Payload)
	require.True(t, bytes.Equal(hello.Payload, q.Payload))
}
