## Overview

The stream package provides an implementation of an asynchronous, reliable, and encrypted communication protocol on top of the Katzenpost network.

This library is provided for establishing reliable bidirectional communication channel between a pair of clients using a shared secret, and a key-value scratchpad service for exchanging messages. From the shared secret, sequences of message storage addresses (32 bytes) and symmetric message encryption keys are derived. Each client runs protocol state machines that fetch, transmit and acknowledge frames of data, and re-transmit unacknowledged frames in order to provide a reliable delivery of data via a lossy storage service. Storage addresses are mapped to nodes published in Katzenpost's Directory Authority system, which runs a service called "Map" that provides a simple lossy storage service where content is limited to a configurable buffer size and automatically expire.

## Usage

Stream implements the io.Writer, io.Reader, and net.Conn interfaces.
Streams need a Transport:
```go
Put(addr []byte, payload []byte) error
Get(addr []byte) ([]byte, error)
PayloadSize() int
```

At present, Stream uses https://github.com/katzenpost/katzenpost/tree/add_reliable_streams/map/client as the Transport.
Map uses a cryptographic capability system that uses blinded ed25519 to derive message storage addresses that are valid ed25519 public keys and are used to verify the payload signed by the corresponding private key.

```go
func DuplexFromSeed(c *Client, initiator bool, secret []byte) RWClient
```
A Transport may be initialized from a shared secret, as currently used by Stream, using the map.DuplexFromSeed method which returns a RWClient.
RWClient implements Transport and encapsulates a pair of capabilities, a read capability to access messages written by another peer and a write capability to write messages to that peer. Only one peer must be the "initiator", which corresponds to the Listener role in a Stream. Instead of deriving both capabilities from the same shared secret, a key exchange may be performed (for example, using PANDA or REUNION with the shared secret) which will enable clients to exchange read-only capabilities so that multiple readers may share the same read-only capability.

### Creating a Stream

```go
func Dial(c Transport, network, addr string) (*Stream, error)
```
Dial creates a new Stream for initiating communication. It takes a transport, network identifier, and address, and returns a Stream initialized with the provided parameters.

```go
func Listen(c Transport, network string, addr *StreamAddr) (*Stream, error)
```
Listen creates a new Stream for listening. It takes a transport, network identifier, and a StreamAddr, and returns a Stream initialized with the provided parameters.

```go
// StreamAddr implements net.Addr
type StreamAddr struct {
	network, address string
}
```
StreamAddr implements net.Addr interface and encapsulates a network and address string. By convesntion, address is base64 encoded and is the shared secret used to initialize a Stream. Stream implements net.Conn, and both tream.LocalAddr() and Stream.RemoteAddr() returns a StreamAddr containing the shared secret.

```go
func ListenDuplex(s *client.Session, network, addr string) (*Stream, error)
```
ListenDuplex creates a new Stream as the Listener, and uses a map.Client initialized from the shared secret for the Transport.

```go
func DialDuplex(s *client.Session, network, addr string) (*Stream, error)
```
DialDuplex creates a new Stream as the Dialer, and uses a map.Client initialized from the shared secret for the Transport.

### Reading and Writing
### Read

```go
func (s *Stream) Read(p []byte) (n int, err error)
```
Read reads data from the stream into the provided byte slice. It blocks until data is available or the stream is closed.

### Write

```go
func (s *Stream) Write(p []byte) (n int, err error)
```
Write writes data to the stream. It blocks until the data is written or the stream is closed.

### Sync

```go
func (s *Stream) Sync() error
```
Sync blocks until the WriteBuf is flushed.

### Closing a Stream
### Close

```go
func (s *Stream) Close() error
```
Close terminates the stream with a final frame and blocks future writes. It does not drain WriteBuf; use Sync() to flush WriteBuf first.

### Halting the workers
### Halt
```go
func (s *Stream) Halt()
```
Stream inherits Halt from https://github.com/katzenpost/katzenpost/core/worker. Calling Halt causes the reader and writer routines to terminate.

### Saving Stream state
```go
func (s *Stream) Save() ([]byte, error)
```
Save() returns the CBOR serialization of a Stream struct

### Restoring Stream state
```go
func LoadStream(s *client.Session, state []byte) (*Stream, error)
```
LoadStream initializes a Stream from state saved by Stream.Save()

### Restarting a Stream
```go
func (s *Stream) Start()
```
Start initializes and starts the reader and writer workers

### Example

```go
// session is provided by https://github.com/katzenpost/katzenpost/client
s := NewStream(session)
r, _ := DialDuplex(session, "", s.RemoteAddr().String())

msg := []byte("Hello World")
s.Write(msg)
io.ReadAtLeast(r, make([]byte, len(msg)), len(msg))
r.Write([]byte("Goodbye World"))
io.ReadAtLeast(s, make([]byte, len(msg)), len(msg))

s.Sync()
s.Close()
r.Sync()
r.Close()
s.Halt()
r.Halt()
```

## unit tests

Unit tests are run using go test:

```bash
go test -v ./...
```

## GitHub CI tests

End-to-End tests are run using dockerized instances of the Katzenpost mixnet.

To start a locally running testnet, navigate to the docker directory of this
repository and follow the README.rst to familiarize yourself with starting and
stopping a local mixnet using the make commands.

Once you have a mixnet running, e.g.:

```bash
git clone https://github.com/katzenpost/katzenpost -b add_reliable_streams && cd katzenpost/docker && make start wait
```

You can then run the end-to-end tests like so:

```bash
  cd ../katzenpost/stream && make dockerdockertest
```

# License

AGPLv3

# Donations

Your donations are welcomed and can be made through Open Collective [here.](https://opencollective.com/the-katzenpost-software-project)

# Supported By

[![NGI](https://katzenpost.mixnetworks.org/_static/images/eu-flag-tiny.jpg)](https://www.ngi.eu/about/)
<a href="https://nlnet.nl"><img src="https://nlnet.nl/logo/banner.svg" width="160" alt="NLnet Foundation"/></a>
<a href="https://nlnet.nl/assure"><img src="https://nlnet.nl/image/logos/NGIAssure_tag.svg" width="160" alt="NGI Assure"/></a>

This project has received funding from:

* NGI Assure Fund, a fund established by NLnet with financial support from the European Commission's Next Generation Internet programme, under the aegis of DG Communications Networks, Content and Technology under grant agreement No 957073.
