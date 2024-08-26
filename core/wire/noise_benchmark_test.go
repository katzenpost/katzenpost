package wire

import (
	"bytes"
	"testing"

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
