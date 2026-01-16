package wire

import (
	"bytes"
	"crypto/subtle"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/katzenpost/nyquist"
	"github.com/katzenpost/nyquist/cipher"
	"github.com/katzenpost/nyquist/hash"
	nyquistkem "github.com/katzenpost/nyquist/kem"
	"github.com/katzenpost/nyquist/pattern"
	"github.com/katzenpost/nyquist/seec"

	"github.com/katzenpost/hpqc/kem/adapter"
	kemhybrid "github.com/katzenpost/hpqc/kem/hybrid"
	"github.com/katzenpost/hpqc/kem/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func BenchmarkPQNoise(b *testing.B) {
	seecGenRand, err := seec.GenKeyPRPAES(rand.Reader, 256)
	if err != nil {
		panic(err)
	}

	protocol := &nyquist.Protocol{
		Pattern: pattern.PqXX,
		KEM: kemhybrid.New(
			"Kyber768-X25519",
			adapter.FromNIKE(ecdh.Scheme(rand.Reader)),
			schemes.ByName("Kyber768"),
		),
		Cipher: cipher.ChaChaPoly,
		Hash:   hash.BLAKE2s,
	}

	_, clientStatic := nyquistkem.GenerateKeypair(protocol.KEM, seecGenRand)
	wireVersion := []byte{0x03} // Prologue indicates version 3.
	maxMsgLen := 1048576

	clientCfg := &nyquist.HandshakeConfig{
		Protocol:       protocol,
		Rng:            rand.Reader,
		Prologue:       wireVersion,
		MaxMessageSize: maxMsgLen,
		KEM: &nyquist.KEMConfig{
			LocalStatic: clientStatic,
			GenKey:      seec.GenKeyPRPAES,
		},
		IsInitiator: true,
	}

	_, serverStatic := nyquistkem.GenerateKeypair(protocol.KEM, seecGenRand)
	serverCfg := &nyquist.HandshakeConfig{
		Protocol:       protocol,
		Rng:            rand.Reader,
		Prologue:       wireVersion,
		MaxMessageSize: maxMsgLen,
		KEM: &nyquist.KEMConfig{
			LocalStatic: serverStatic,
			GenKey:      seec.GenKeyPRPAES,
		},
		IsInitiator: false,
	}

	var serverMsg3 []byte
	var serverMsg3Plaintext []byte
	const plaintext = "I tell you: one must still have chaos in oneself in order to be able to give birth to a dancing star. I tell you: you still have chaos within you."

	for n := 0; n < b.N; n++ {

		clientHs, err := nyquist.NewHandshake(clientCfg)
		if err != nil {
			panic(err)
		}
		defer clientHs.Reset()

		serverHs, err := nyquist.NewHandshake(serverCfg)
		if err != nil {
			panic(err)
		}
		defer serverHs.Reset()

		clientSs := clientHs.SymmetricState()
		if clientSs == nil {
			panic("found nil")
		}
		clientCs := clientSs.CipherState()
		if clientCs == nil {
			panic("found nil")
		}

		var (
			authLen = 1 + MaxAdditionalDataLength + 4
		)

		// (client) -> (prologue), e
		clientMsg1, err := clientHs.WriteMessage(nil, nil)
		if err != nil {
			panic(err)
		}

		_, err = serverHs.ReadMessage(nil, clientMsg1)
		if err != nil {
			panic(err)
		}

		// -> ekem, s, (auth)
		rawAuth := make([]byte, authLen)
		serverMsg1, err := serverHs.WriteMessage(nil, rawAuth)
		if err != nil {
			panic(err)
		}

		_, err = clientHs.ReadMessage(nil, serverMsg1)
		if err != nil {
			panic(err)
		}

		// -> skem, s, (auth)
		clientMsg2, err := clientHs.WriteMessage(nil, rawAuth)
		if err != nil {
			panic(err)
		}

		_, err = serverHs.ReadMessage(nil, clientMsg2)
		if err != nil {
			panic(err)
		}

		// (server) -> skem
		serverMsg2, err := serverHs.WriteMessage(nil, nil)
		if err != nyquist.ErrDone {
			panic(err)
		}

		_, err = clientHs.ReadMessage(nil, serverMsg2)
		if err != nyquist.ErrDone {
			panic(err)
		}

		clientStatus := clientHs.GetStatus()
		serverStatus := serverHs.GetStatus()

		// send messages

		_, clientrx := clientStatus.CipherStates[0], clientStatus.CipherStates[1]
		_, servertx := serverStatus.CipherStates[0], serverStatus.CipherStates[1]

		serverMsg3, err = servertx.EncryptWithAd(nil, nil, []byte(plaintext))
		if err != nil {
			b.Fatal(err)
		}

		serverMsg3Plaintext, err = clientrx.DecryptWithAd(nil, nil, serverMsg3)
		if err != nil {
			b.Fatal(err)
		}
	}

	if !bytes.Equal(serverMsg3Plaintext[:], []byte(plaintext)) {
		b.Fatal("decrypted plaintext does not match")
	}
}

// benchAuthenticator is a simple authenticator for benchmarking
type benchAuthenticator struct {
	expectedCreds *PeerCredentials
}

func (a *benchAuthenticator) IsPeerValid(peer *PeerCredentials) bool {
	if subtle.ConstantTimeCompare(a.expectedCreds.AdditionalData, peer.AdditionalData) != 1 {
		return false
	}
	blob1, err := a.expectedCreds.PublicKey.MarshalBinary()
	if err != nil {
		return false
	}
	blob2, err := peer.PublicKey.MarshalBinary()
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(blob1, blob2) == 1
}

// BenchmarkPQNoiseSessionTCP benchmarks the full wire.Session handshake over TCP
func BenchmarkPQNoiseSessionTCP(b *testing.B) {
	scheme := testingScheme

	// Generate credentials for client and server
	clientPubKey, clientPrivKey, err := scheme.GenerateKeyPair()
	if err != nil {
		b.Fatalf("failed to generate client keypair: %v", err)
	}
	clientCreds := &PeerCredentials{
		AdditionalData: []byte("client@benchmark.test"),
		PublicKey:      clientPubKey,
	}

	serverPubKey, serverPrivKey, err := scheme.GenerateKeyPair()
	if err != nil {
		b.Fatalf("failed to generate server keypair: %v", err)
	}
	serverCreds := &PeerCredentials{
		AdditionalData: []byte("server@benchmark.test"),
		PublicKey:      serverPubKey,
	}

	// Create sphinx geometry for session
	nike := ecdh.Scheme(rand.Reader)
	geometry := geo.GeometryFromUserForwardPayloadLength(nike, 2000, true, 5)

	// Start TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Close()
	addr := listener.Addr().String()

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		var wg sync.WaitGroup
		var clientErr, serverErr error

		// Server goroutine
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn, err := listener.Accept()
			if err != nil {
				serverErr = err
				return
			}
			defer conn.Close()

			serverCfg := &SessionConfig{
				KEMScheme:         scheme,
				Geometry:          geometry,
				Authenticator:     &benchAuthenticator{expectedCreds: clientCreds},
				AdditionalData:    serverCreds.AdditionalData,
				AuthenticationKey: serverPrivKey,
				RandomReader:      rand.Reader,
			}

			session, err := NewSession(serverCfg, false)
			if err != nil {
				serverErr = err
				return
			}
			defer session.Close()

			if err := session.Initialize(conn); err != nil {
				serverErr = err
				return
			}
		}()

		// Client goroutine
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn, err := net.Dial("tcp", addr)
			if err != nil {
				clientErr = err
				return
			}
			defer conn.Close()

			clientCfg := &SessionConfig{
				KEMScheme:         scheme,
				Geometry:          geometry,
				Authenticator:     &benchAuthenticator{expectedCreds: serverCreds},
				AdditionalData:    clientCreds.AdditionalData,
				AuthenticationKey: clientPrivKey,
				RandomReader:      rand.Reader,
			}

			session, err := NewSession(clientCfg, true)
			if err != nil {
				clientErr = err
				return
			}
			defer session.Close()

			if err := session.Initialize(conn); err != nil {
				clientErr = err
				return
			}
		}()

		wg.Wait()

		if serverErr != nil {
			b.Fatalf("server error: %v", serverErr)
		}
		if clientErr != nil {
			b.Fatalf("client error: %v", clientErr)
		}
	}
}

// BenchmarkPQNoiseSessionPipe benchmarks the full wire.Session handshake over net.Pipe
// This isolates the handshake from TCP overhead
func BenchmarkPQNoiseSessionPipe(b *testing.B) {
	scheme := testingScheme

	// Generate credentials for client and server
	clientPubKey, clientPrivKey, err := scheme.GenerateKeyPair()
	if err != nil {
		b.Fatalf("failed to generate client keypair: %v", err)
	}
	clientCreds := &PeerCredentials{
		AdditionalData: []byte("client@benchmark.test"),
		PublicKey:      clientPubKey,
	}

	serverPubKey, serverPrivKey, err := scheme.GenerateKeyPair()
	if err != nil {
		b.Fatalf("failed to generate server keypair: %v", err)
	}
	serverCreds := &PeerCredentials{
		AdditionalData: []byte("server@benchmark.test"),
		PublicKey:      serverPubKey,
	}

	// Create sphinx geometry for session
	nike := ecdh.Scheme(rand.Reader)
	geometry := geo.GeometryFromUserForwardPayloadLength(nike, 2000, true, 5)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		clientConn, serverConn := net.Pipe()
		var wg sync.WaitGroup
		var clientErr, serverErr error

		// Server goroutine
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer serverConn.Close()

			serverCfg := &SessionConfig{
				KEMScheme:         scheme,
				Geometry:          geometry,
				Authenticator:     &benchAuthenticator{expectedCreds: clientCreds},
				AdditionalData:    serverCreds.AdditionalData,
				AuthenticationKey: serverPrivKey,
				RandomReader:      rand.Reader,
			}

			session, err := NewSession(serverCfg, false)
			if err != nil {
				serverErr = err
				return
			}
			defer session.Close()

			if err := session.Initialize(serverConn); err != nil {
				serverErr = err
				return
			}
		}()

		// Client goroutine
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer clientConn.Close()

			clientCfg := &SessionConfig{
				KEMScheme:         scheme,
				Geometry:          geometry,
				Authenticator:     &benchAuthenticator{expectedCreds: serverCreds},
				AdditionalData:    clientCreds.AdditionalData,
				AuthenticationKey: clientPrivKey,
				RandomReader:      rand.Reader,
			}

			session, err := NewSession(clientCfg, true)
			if err != nil {
				clientErr = err
				return
			}
			defer session.Close()

			if err := session.Initialize(clientConn); err != nil {
				clientErr = err
				return
			}
		}()

		wg.Wait()

		if serverErr != nil {
			b.Fatalf("server error: %v", serverErr)
		}
		if clientErr != nil {
			b.Fatalf("client error: %v", clientErr)
		}
	}
}

// BenchmarkPQNoiseSessionPipeDetailed benchmarks each phase of the handshake separately
// to identify where time is spent
func BenchmarkPQNoiseSessionPipeDetailed(b *testing.B) {
	scheme := testingScheme

	// Generate credentials for client and server
	clientPubKey, clientPrivKey, err := scheme.GenerateKeyPair()
	if err != nil {
		b.Fatalf("failed to generate client keypair: %v", err)
	}
	clientCreds := &PeerCredentials{
		AdditionalData: []byte("client@benchmark.test"),
		PublicKey:      clientPubKey,
	}

	serverPubKey, serverPrivKey, err := scheme.GenerateKeyPair()
	if err != nil {
		b.Fatalf("failed to generate server keypair: %v", err)
	}
	serverCreds := &PeerCredentials{
		AdditionalData: []byte("server@benchmark.test"),
		PublicKey:      serverPubKey,
	}

	// Create sphinx geometry for session
	nike := ecdh.Scheme(rand.Reader)
	geometry := geo.GeometryFromUserForwardPayloadLength(nike, 2000, true, 5)

	// Run benchmark and collect timing stats
	var totalTime, minTime, maxTime int64
	minTime = int64(^uint64(0) >> 1) // max int64

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		clientConn, serverConn := net.Pipe()
		var wg sync.WaitGroup
		var clientErr, serverErr error
		var handshakeDuration int64

		// Server goroutine
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer serverConn.Close()

			serverCfg := &SessionConfig{
				KEMScheme:         scheme,
				Geometry:          geometry,
				Authenticator:     &benchAuthenticator{expectedCreds: clientCreds},
				AdditionalData:    serverCreds.AdditionalData,
				AuthenticationKey: serverPrivKey,
				RandomReader:      rand.Reader,
			}

			session, err := NewSession(serverCfg, false)
			if err != nil {
				serverErr = err
				return
			}
			defer session.Close()

			if err := session.Initialize(serverConn); err != nil {
				serverErr = err
				return
			}
		}()

		// Client goroutine with timing
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer clientConn.Close()

			clientCfg := &SessionConfig{
				KEMScheme:         scheme,
				Geometry:          geometry,
				Authenticator:     &benchAuthenticator{expectedCreds: serverCreds},
				AdditionalData:    clientCreds.AdditionalData,
				AuthenticationKey: clientPrivKey,
				RandomReader:      rand.Reader,
			}

			session, err := NewSession(clientCfg, true)
			if err != nil {
				clientErr = err
				return
			}
			defer session.Close()

			start := time.Now()
			if err := session.Initialize(clientConn); err != nil {
				clientErr = err
				return
			}
			handshakeDuration = time.Since(start).Nanoseconds()
		}()

		wg.Wait()

		if serverErr != nil {
			b.Fatalf("server error: %v", serverErr)
		}
		if clientErr != nil {
			b.Fatalf("client error: %v", clientErr)
		}

		totalTime += handshakeDuration
		if handshakeDuration < minTime {
			minTime = handshakeDuration
		}
		if handshakeDuration > maxTime {
			maxTime = handshakeDuration
		}
	}

	b.StopTimer()

	if b.N > 0 {
		avgTime := time.Duration(totalTime / int64(b.N))
		b.ReportMetric(float64(avgTime.Microseconds()), "avg_µs/handshake")
		b.ReportMetric(float64(time.Duration(minTime).Microseconds()), "min_µs/handshake")
		b.ReportMetric(float64(time.Duration(maxTime).Microseconds()), "max_µs/handshake")
	}
}

func BenchmarkClassicalNoise(b *testing.B) {
	protocol, err := nyquist.NewProtocol("Noise_XX_25519_ChaChaPoly_BLAKE2s")
	if err != nil {
		panic(err)
	}

	clientStatic, err := protocol.DH.GenerateKeypair(rand.Reader)
	if err != nil {
		panic(err)
	}

	clientCfg := &nyquist.HandshakeConfig{
		Protocol: protocol,
		DH: &nyquist.DHConfig{
			LocalStatic: clientStatic,
		},
		IsInitiator: true,
	}

	serverStatic, err := protocol.DH.GenerateKeypair(rand.Reader)
	if err != nil {
		panic(err)
	}

	serverCfg := &nyquist.HandshakeConfig{
		Protocol: protocol,
		DH: &nyquist.DHConfig{
			LocalStatic: serverStatic,
		},
		IsInitiator: false,
	}

	var serverMsg3 []byte
	var serverMsg3Plaintext []byte
	const plaintext = "I tell you: one must still have chaos in oneself in order to be able to give birth to a dancing star. I tell you: you still have chaos within you."

	for n := 0; n < b.N; n++ {

		clientHs, err := nyquist.NewHandshake(clientCfg)
		if err != nil {
			panic(err)
		}
		defer clientHs.Reset()

		serverHs, err := nyquist.NewHandshake(serverCfg)
		if err != nil {
			panic(err)
		}
		defer serverHs.Reset()

		clientSs := clientHs.SymmetricState()
		if clientSs == nil {
			panic("found nil")
		}
		clientCs := clientSs.CipherState()
		if clientCs == nil {
			panic("found nil")
		}

		var (
			authLen = 1 + MaxAdditionalDataLength + 4
		)

		// (client) -> (prologue), e
		clientMsg1, err := clientHs.WriteMessage(nil, nil)
		if err != nil {
			panic(err)
		}

		_, err = serverHs.ReadMessage(nil, clientMsg1)
		if err != nil {
			panic(err)
		}

		// -> ekem, s, (auth)
		rawAuth := make([]byte, authLen)
		serverMsg1, err := serverHs.WriteMessage(nil, rawAuth)
		if err != nil {
			panic(err)
		}

		_, err = clientHs.ReadMessage(nil, serverMsg1)
		if err != nil {
			panic(err)
		}

		// -> skem, s, (auth)
		clientMsg2, err := clientHs.WriteMessage(nil, rawAuth)
		if err != nyquist.ErrDone {
			panic(err)
		}

		_, err = serverHs.ReadMessage(nil, clientMsg2)
		if err != nyquist.ErrDone {
			panic(err)
		}

		// (server) -> skem
		serverMsg2, err := serverHs.WriteMessage(nil, nil)
		if err != nyquist.ErrDone {
			panic(err)
		}

		_, err = clientHs.ReadMessage(nil, serverMsg2)
		if err != nyquist.ErrDone {
			panic(err)
		}

		clientStatus := clientHs.GetStatus()
		serverStatus := serverHs.GetStatus()

		// send messages

		_, clientrx := clientStatus.CipherStates[0], clientStatus.CipherStates[1]
		_, servertx := serverStatus.CipherStates[0], serverStatus.CipherStates[1]

		serverMsg3, err = servertx.EncryptWithAd(nil, nil, []byte(plaintext))
		if err != nil {
			b.Fatal(err)
		}

		serverMsg3Plaintext, err = clientrx.DecryptWithAd(nil, nil, serverMsg3)
		if err != nil {
			b.Fatal(err)
		}
	}

	if !bytes.Equal(serverMsg3Plaintext[:], []byte(plaintext)) {
		b.Fatal("decrypted plaintext does not match")
	}
}
