package client

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
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

func (smp *SimpleMeetingPlace) Exchange(log func(string, ...interface{}), id, message []byte, shutdown chan struct{}) ([]byte, error) {
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
					return nil, ShutdownErr
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
	kx, err := NewKeyExchange(rand.Reader, mp, secret, []byte{1})
	require.NoError(err)

	serialised := kx.Marshal()
	_, err = UnmarshalKeyExchange(rand.Reader, mp, serialised)
	require.NoError(err)
}

func runKX(resultChan chan interface{}, log func(string, ...interface{}), mp MeetingPlace, secret []byte, message []byte) {
	kx, err := NewKeyExchange(rand.Reader, mp, secret, message)
	if err != nil {
		resultChan <- err
	}
	kx.Log = log
	kx.Testing = true
	reply, err := kx.Run()
	if err != nil {
		resultChan <- err
	}
	resultChan <- reply
}

func TestKeyExchange(t *testing.T) {
	require := require.New(t)

	a, b := make(chan interface{}), make(chan interface{})
	mp := NewSimpleMeetingPlace()
	secret := []byte("foo")
	msg1 := []byte("test1")
	msg2 := []byte("test2")
	go runKX(a, t.Logf, mp, secret, msg1)
	go runKX(b, t.Logf, mp, secret, msg2)

	result := <-a
	reply, ok := result.([]byte)
	require.True(ok)
	require.Equal(reply, msg2)

	result = <-b
	reply, ok = result.([]byte)
	require.True(ok)
	require.Equal(reply, msg1)
}

func TestStartStop(t *testing.T) {
	require := require.New(t)

	mp := NewSimpleMeetingPlace()
	secret := []byte("foo")
	msg1 := []byte("test1")
	msg2 := []byte("test2")
	a := make(chan interface{})
	go runKX(a, t.Logf, mp, secret, msg1)

	panicLog := func(format string, args ...interface{}) {
		fmt.Printf(format, args...)
		t.Logf(format, args...)
		panic("unwind")
	}

	kx, err := NewKeyExchange(rand.Reader, mp, secret, msg2)
	require.NoError(err)

	serialised := kx.Marshal()
	kx.Log = panicLog
	kx.Testing = true
	count := 0

	var result []byte
	done := false
	for !done {
		kx, err := UnmarshalKeyExchange(rand.Reader, mp, serialised)
		require.NoError(err)

		kx.Log = panicLog
		kx.Testing = true

		func() {
			defer func() {
				if count < 2 {
					serialised = kx.Marshal()
					recover()
				}
				count++
			}()
			result, err = kx.Run()
			require.NoError(err)
			done = true
		}()
	}

	require.Equal(result, msg1)
}
