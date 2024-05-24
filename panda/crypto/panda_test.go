package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"
	"sync"
	"testing"
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

func (smp *SimpleMeetingPlace) Exchange(id, message []byte, shutdown <-chan interface{}) ([]byte, error) {
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
	t.Parallel()
	require := require.New(t)

	secret := []byte("foo")
	srv := []byte("this should be 32 bytes long....")
	mp := NewSimpleMeetingPlace()

	logBackend, err := log.New("", "debug", false)
	require.NoError(err)

	shutdownChan := make(chan interface{})
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
	kx, err := NewKeyExchange(rand.Reader, logBackend.GetLogger("a_kx"), mp, srv, secret, []byte{1}, contactID, pandaChan, shutdownChan)
	require.NoError(err)

	serialised := kx.Marshal()
	_, err = UnmarshalKeyExchange(rand.Reader, logBackend.GetLogger("unmarshal_kx"), mp, serialised, contactID, pandaChan, shutdownChan)
	require.NoError(err)
}

func getKX(resultChan chan interface{}, log *logging.Logger, mp MeetingPlace, srv []byte, secret []byte, message []byte) (*KeyExchange, chan interface{}, error) {

	shutdownChan := make(chan interface{})
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
	kx, err := NewKeyExchange(rand.Reader, log, mp, srv, secret, message, contactID, pandaChan, shutdownChan)
	if err != nil {
		resultChan <- err
	}
	return kx, shutdownChan, err
}

func runKX(resultChan chan interface{}, log *logging.Logger, mp MeetingPlace, srv []byte, secret []byte, message []byte) {
	kx, _, err := getKX(resultChan, log, mp, srv, secret, message)
	if err == nil {
		kx.Run()
	} else {
		panic(err)
	}
}

func TestKeyExchange(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	a, b := make(chan interface{}), make(chan interface{})
	mp := NewSimpleMeetingPlace()
	secret := []byte("foo")
	srv := []byte("this should be 32 bytes long....")
	msg1 := []byte("test1")
	msg2 := []byte("test2")

	logBackend, err := log.New("", "debug", false)
	require.NoError(err)

	go runKX(a, logBackend.GetLogger("a_kx"), mp, srv, secret, msg1)
	go runKX(b, logBackend.GetLogger("b_kx"), mp, srv, secret, msg2)

	result := <-a
	reply, ok := result.([]byte)
	require.True(ok)
	require.Equal(reply, msg2)

	result = <-b
	reply, ok = result.([]byte)
	require.True(ok)
	require.Equal(reply, msg1)
}

// XXX FIXME. This test is broken and sometimes deadlocks or sometimes fails.
func NoTestUpdateSRV(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	a, b := make(chan interface{}), make(chan interface{})
	mp := NewSimpleMeetingPlace()
	secret := []byte("foo")
	srv1 := []byte("this should be 32 bytes long....")
	srv2 := []byte("yet one more 32 byte long string")
	msg1 := []byte("test1")
	msg2 := []byte("test2")

	logBackend, err := log.New("", "debug", false)
	require.NoError(err)

	kx1, shutdownChan, err := getKX(a, logBackend.GetLogger("a_kx"), mp, srv1, secret, msg1)
	require.NoError(err)
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		kx1.Run()
		wg.Done()
	}()
	go runKX(b, logBackend.GetLogger("b_kx"), mp, srv2, secret, msg2)

	// stop the exchange, update the srv, and restart the exchange
	var foo struct{}
	shutdownChan <- foo
	wg.Wait()
	kx1.SetSharedRandom(srv2)
	go kx1.Run()

	result := <-a
	reply, ok := result.([]byte)
	require.True(ok)
	require.Equal(reply, msg2)

	result = <-b
	reply, ok = result.([]byte)
	require.True(ok)
	require.Equal(reply, msg1)
}

func runKXWithSerialize(resultChan chan interface{}, log *logging.Logger, mp MeetingPlace, srv []byte, secret []byte, message []byte) {

	shutdownChan := make(chan interface{})
	contactID := uint64(123)
	pandaChan := make(chan PandaUpdate)
	kx, err := NewKeyExchange(rand.Reader, log, mp, srv, secret, message, contactID, pandaChan, shutdownChan)

	if err != nil {
		resultChan <- err
		return
	}
	kx.log = log
	go kx.Run()

	go func() {
		var reply []byte
		for {
			select {
			case pandaUpdate := <-pandaChan:
				close(shutdownChan)
				shutdownChan = make(chan interface{})
				sr := kx.Marshal()
				kx, err = UnmarshalKeyExchange(rand.Reader, log, mp, sr, contactID, pandaChan, shutdownChan)
				kx.pandaChan = pandaChan
				kx.shutdownChan = shutdownChan
				kx.contactID = contactID
				if err != nil {
					resultChan <- err
					return
				}
				go kx.Run()

				reply = pandaUpdate.Result
				if reply != nil {
					resultChan <- reply
				}
			default:
			}
		}
	}()
}

func TestKeyExchangeWithSerialization(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	a, b := make(chan interface{}), make(chan interface{})
	mp := NewSimpleMeetingPlace()
	secret := []byte("foo")
	srv := []byte("this should be 32 bytes long....")
	msg1 := []byte("test1")
	msg2 := []byte("test2")

	logBackend, err := log.New("", "debug", false)
	require.NoError(err)

	go runKX(a, logBackend.GetLogger("a_kx"), mp, srv, secret, msg1)
	go runKXWithSerialize(b, logBackend.GetLogger("b_kx"), mp, srv, secret, msg2)

	result := <-a
	reply, ok := result.([]byte)
	require.True(ok)
	require.Equal(reply, msg2)

	result = <-b
	reply, ok = result.([]byte)
	require.True(ok)
	require.Equal(reply, msg1)
}
