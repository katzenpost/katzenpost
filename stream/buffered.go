package stream

import (
	"bytes"
	"errors"
	"io"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/core/worker"
)

// BufferedStream holds a Stream and Buffer of bytes that are used with cbor.Decoder
type BufferedStream struct {
	worker.Worker
	sync.Mutex
	Stream *Stream
	Buffer *bytes.Buffer
}

// Start starts BufferedStreams Stream
func (b *BufferedStream) Start() {
	// Start/Stop Stream
	b.Stream.Start()
	// Halt Stream along with this BufferedStream
	b.Go(func() {
		<-b.HaltCh()
		b.Stream.Halt()
	})
}

// CBORDecodeAsync is the routine that reads from the Stream until an instance is deserialized
// or the stream is closed. It returns the deserialiezd instance or error via a channel
func (b *BufferedStream) CBORDecodeAsync(instance interface{}) chan interface{} {
	result := make(chan interface{}, 1)
	b.Go(func() {
		b.Lock() // BufferedStreams are not to be shared
		if b.Buffer == nil {
			b.Buffer = new(bytes.Buffer)
		}
		defer b.Unlock()
		defer close(result)
		var dec *cbor.Decoder
		for {
			// buf will contain the bytes read by the cbor Decoder using a TeeReader
			buf := new(bytes.Buffer)

			// if the Buffer contains data, read from it first
			if b.Buffer.Len() > 0 {
				dec = cbor.NewDecoder(io.TeeReader(io.MultiReader(b.Buffer, b.Stream), buf))
			} else {
				dec = cbor.NewDecoder(io.TeeReader(b.Stream, buf))
			}

			err := dec.Decode(instance)
			if buf.Len() > 0 && b.Buffer.Len() > 0 {
				n, err := io.Copy(buf, b.Buffer) // keep bytes unconsumed from Buffer
				if err != nil {
					result <- err
					return
				}
				if int(n) < b.Buffer.Len() {
					result <- errors.New("Failed to save buffered bytes")
					return
				}
			}
			buf.Next(dec.NumBytesRead()) // dump the successfully decoded bytes (0 on error)
			b.Buffer = buf               // save read-but-not-decoded bytes

			if err != nil {
				// if Stream was closed during Decode, it's over.
				if err == io.EOF {
					result <- err
					return
				}
				//XXX: backoff rety <-time.After(1*time.Second)//tryagain later
				continue
			}
			select {
			case <-b.HaltCh():
				result <- errors.New("Halted")
				return
			case result <- instance:
			}
			return
		}
	})
	return result
}

// Write calls Stream.Write
func (s *BufferedStream) Write(p []byte) (n int, err error) {
	return s.Stream.Write(p)
}

// Read calls Stream.Read
func (s *BufferedStream) Read(p []byte) (n int, err error) {
	return s.Stream.Read(p)
}

// Close calls Stream.Close
func (s *BufferedStream) Close() error {
	return s.Stream.Close()
}

// CBORDecode deserializes CBOR from Stream into the instance passed
func (b *BufferedStream) CBORDecode(instance interface{}) error {
	result := b.CBORDecodeAsync(instance)
	select {
	case <-b.HaltCh():
		return ErrHalted
	case r, ok := <-result:
		// channel closed by worker on Halt
		if !ok {
			return ErrHalted
		}
		// if result was type error:
		if e, ok := r.(error); ok {
			return e
		}
	}
	return nil
}
