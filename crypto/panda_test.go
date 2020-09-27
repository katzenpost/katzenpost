package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"sync"
	"testing"

	"github.com/katzenpost/core/log"
	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"
)

const paddingSize = 1 << 16

type pair struct {
	messages [2][]byte
}

type SimpleMeetingPlace struct {
	sync.Mutex
	values   map[string]*pair
	wakeChan chan bool
}

func (smp *SimpleMeetingPlace) Padding() int {
	return paddingSize
}

func (smp *SimpleMeetingPlace) Exchange(id, message []byte, shutdown chan struct{}) ([]byte, error) {
	i := string(id)

	smp.Lock()

	var p *pair
	if p = smp.values[string(id)]; p == nil {
		p = new(pair)
		smp.values[i] = p
		p.messages[0] = message
	}

	for i := 0; i < 2; i++ {
		if len(p.messages[i]) == 0 || bytes.Equal(p.messages[i], message) {
			if len(p.messages[i]) == 0 {
				p.messages[i] = message
				select {
				case smp.wakeChan <- true:
				default:
				}
			}
			for {
				other := p.messages[i^1]
				if len(other) > 0 {
					smp.Unlock()
					return other, nil
				}
				smp.Unlock()
				select {
				case <-smp.wakeChan:
					smp.Lock()
				case <-shutdown:
					return nil, errors.New(ShutdownErrMessage)
				}
			}
		}
	}

	return nil, errors.New("more than two messages for a single id")
}

func NewSimpleMeetingPlace() *SimpleMeetingPlace {
	s := &SimpleMeetingPlace{
		values:   make(map[string]*pair),
		wakeChan: make(chan bool),
	}
	return s
}

func TestSerialise(t *testing.T) {
	require := require.New(t)

	secret := []byte("foo")
	mp := NewSimpleMeetingPlace()

	logBackend, err := log.New("", "debug", false)
	require.NoError(err)

	shutdownChan := make(chan struct{})
	go func() {
		<-shutdownChan
	}()
	pandaChan := make(chan PandaUpdate)
	go func() {
		for {
			<-pandaChan
		}
	}()

	contactID := uint64(123)
	kx, err := NewKeyExchange(rand.Reader, logBackend.GetLogger("a_kx"), mp, secret, []byte{1}, contactID, pandaChan, shutdownChan)
	require.NoError(err)

	serialised := kx.Marshal()
	_, err = UnmarshalKeyExchange(rand.Reader, logBackend.GetLogger("unmarshal_kx"), mp, serialised, contactID, pandaChan, shutdownChan)
	require.NoError(err)
}

func runKX(resultChan chan interface{}, log *logging.Logger, mp MeetingPlace, secret []byte, message []byte) {

	shutdownChan := make(chan struct{})
	go func() {
		<-shutdownChan
	}()

	pandaChan := make(chan PandaUpdate)
	go func() {
		var reply []byte
		for {
			pandaUpdate := <-pandaChan
			reply = pandaUpdate.Result
			if reply != nil {
				resultChan <- reply
			}
		}
	}()
	contactID := uint64(123)
	kx, err := NewKeyExchange(rand.Reader, log, mp, secret, message, contactID, pandaChan, shutdownChan)
	if err != nil {
		resultChan <- err
	}
	kx.log = log
	kx.Run()
	if err != nil {
		resultChan <- err
	}
}

func TestKeyExchange(t *testing.T) {
	require := require.New(t)

	a, b := make(chan interface{}), make(chan interface{})
	mp := NewSimpleMeetingPlace()
	secret := []byte("foo")
	msg1 := []byte("test1")
	msg2 := []byte("test2")

	logBackend, err := log.New("", "debug", false)
	require.NoError(err)

	go runKX(a, logBackend.GetLogger("a_kx"), mp, secret, msg1)
	go runKX(b, logBackend.GetLogger("b_kx"), mp, secret, msg2)

	result := <-a
	reply, ok := result.([]byte)
	require.True(ok)
	require.Equal(reply, msg2)

	result = <-b
	reply, ok = result.([]byte)
	require.True(ok)
	require.Equal(reply, msg1)
}
