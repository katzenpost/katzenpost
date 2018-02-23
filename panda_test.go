package panda

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSerialise(t *testing.T) {
	require := require.New(t)

	secret := SharedSecret{
		Secret: "foo",
	}
	mp := NewSimpleMeetingPlace()
	kx, err := NewKeyExchange(rand.Reader, mp, &secret, []byte{1})
	require.NoError(err, "wtf")

	serialised := kx.Marshal()
	_, err = UnmarshalKeyExchange(rand.Reader, mp, serialised)
	require.NoError(err, "wtf")
}

func runKX(resultChan chan interface{}, log func(string, ...interface{}), mp MeetingPlace, secret *SharedSecret, message []byte) {
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
	secret := SharedSecret{
		Secret: "foo",
	}

	msg1 := []byte("test1")
	msg2 := []byte("test2")
	go runKX(a, t.Logf, mp, &secret, msg1)
	go runKX(b, t.Logf, mp, &secret, msg2)

	result := <-a
	reply, ok := result.([]byte)
	require.True(ok, "wtf")
	require.Equal(reply, msg2, "wtf")

	result = <-b
	if reply, ok := result.([]byte); ok {
		if !bytes.Equal(reply, msg1) {
			t.Errorf("Bad result from kx: got %x, want %x", reply, msg1)
		}
	} else {
		t.Errorf("Error from key exchange: %s", result)
	}
}

func TestStartStop(t *testing.T) {
	require := require.New(t)

	mp := NewSimpleMeetingPlace()
	secret := SharedSecret{
		Secret: "foo",
	}

	msg1 := []byte("test1")
	msg2 := []byte("test2")
	a := make(chan interface{})
	go runKX(a, t.Logf, mp, &secret, msg1)

	panicLog := func(format string, args ...interface{}) {
		fmt.Printf(format, args...)
		t.Logf(format, args...)
		panic("unwind")
	}

	kx, err := NewKeyExchange(rand.Reader, mp, &secret, msg2)
	require.NoError(err, "wtf")

	serialised := kx.Marshal()
	kx.Log = panicLog
	kx.Testing = true
	count := 0

	var result []byte
	done := false
	for !done {
		kx, err := UnmarshalKeyExchange(rand.Reader, mp, serialised)
		require.NoError(err, "wtf")

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
			require.NoError(err, "wtf")
			done = true
		}()
	}

	require.Equal(result, msg1, "wtf")
}

func TestSecretStringGeneration(t *testing.T) {
	require := require.New(t)

	s, err := NewSecretString(rand.Reader)
	require.NoError(err, "wtf")
	require.True(isValidSecretString(s), fmt.Sprintf("Generated secret string isn't valid: %s", s))
	require.True(IsAcceptableSecretString(s), fmt.Sprintf("Generated secret string isn't acceptable: %s", s))

	s = s[:8] + "," + s[9:]
	require.False(isValidSecretString(s), fmt.Sprintf("Corrupt secret string is valid: %s", s))

	s = "498572384"
	require.True(IsAcceptableSecretString(s), fmt.Sprintf("Random secret string isn't acceptable: %s", s))
	require.False(isValidSecretString(s), fmt.Sprintf("Random secret string is valid: %s", s))
}
