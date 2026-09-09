// main.go - Generates cross-implementation test vectors for the Sphinx
// primitive layer (Hash, MAC, Stream cipher, SPRP, KDF), for the Lean port
// in CryptWalker (https://github.com/katzenpost/CryptWalker).
//
// Mirrors the envelope format used by
// github.com/katzenpost/hpqc/testvectors/cmd/generate, so the Lean-side
// parser code can be copy-adapted from CryptWalker's existing test.lean
// files.
//
// Run from the repository root:
//
//	go run ./core/sphinx/testvectors/cmd/generate
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/crypto/hkdf"

	"github.com/katzenpost/katzenpost/core/sphinx/internal/crypto"
)

type vectorFile struct {
	FormatVersion int    `json:"format_version"`
	Generator     string `json:"generator"`
	Primitive     string `json:"primitive"`
	Description   string `json:"description"`
	Vectors       any    `json:"vectors"`
}

const generatorName = "github.com/katzenpost/katzenpost/core/sphinx/testvectors/cmd/generate"

func writeVectorFile(path, primitive, description string, vectors any) {
	vf := vectorFile{
		FormatVersion: 1,
		Generator:     generatorName,
		Primitive:     primitive,
		Description:   description,
		Vectors:       vectors,
	}
	b, err := json.MarshalIndent(vf, "", "  ")
	if err != nil {
		panic(err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil {
		panic(err)
	}
	fmt.Println("wrote", path)
}

// pattern returns a deterministic byte sequence of length n: byte i is
// (start+i) mod 256. Used in place of random test inputs so vectors are
// reproducible without a seeded RNG.
func pattern(start byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

func hx(b []byte) string { return hex.EncodeToString(b) }

// --- Hash (SHA-512/256, replay-tag usage) ---

type hashVector struct {
	Name      string `json:"name"`
	InputHex  string `json:"input_hex"`
	OutputHex string `json:"output_hex"`
}

func genHash() {
	inputs := map[string][]byte{
		"empty":                  {},
		"abc":                    []byte("abc"),
		"32B_group_element_like": pattern(0x00, 32),
		"one_sha512_block_128B":  pattern(0x00, 128),
	}
	names := []string{"empty", "abc", "32B_group_element_like", "one_sha512_block_128B"}
	var vecs []hashVector
	for _, name := range names {
		in := inputs[name]
		out := crypto.Hash(in)
		vecs = append(vecs, hashVector{Name: name, InputHex: hx(in), OutputHex: hx(out[:])})
	}
	writeVectorFile("core/sphinx/testvectors/primitives/hash_sha512_256.json",
		"sha512_256",
		"SHA-512/256 as used by Sphinx for the replay tag (crypto.Hash).",
		vecs)
}

// --- MAC (HMAC-SHA256, Sphinx's header MAC) ---

type macVector struct {
	Name   string `json:"name"`
	KeyHex string `json:"key_hex"`
	MsgHex string `json:"msg_hex"`
	MacHex string `json:"mac_hex"`
}

func genMAC() {
	key := [32]byte{}
	copy(key[:], pattern(0x00, 32))
	msgs := []struct {
		name string
		msg  []byte
	}{
		{"empty", []byte{}},
		{"abc", []byte("abc")},
		{"64B_header_like", pattern(0x10, 64)},
	}
	var vecs []macVector
	for _, m := range msgs {
		h := crypto.NewMAC(&key)
		h.Write(m.msg)
		tag := h.Sum(nil)
		vecs = append(vecs, macVector{Name: m.name, KeyHex: hx(key[:]), MsgHex: hx(m.msg), MacHex: hx(tag)})
	}
	writeVectorFile("core/sphinx/testvectors/primitives/mac_hmac_sha256.json",
		"hmac_sha256",
		"HMAC-SHA256 as used by Sphinx's header MAC (crypto.NewMAC), full 32-byte tag.",
		vecs)
}

// --- Stream (AES-256-CTR, Sphinx's header/routing-info keystream) ---

type streamVector struct {
	Name         string `json:"name"`
	KeyHex       string `json:"key_hex"`
	IvHex        string `json:"iv_hex"`
	Length       int    `json:"length"`
	KeystreamHex string `json:"keystream_hex"`
}

func genStream() {
	key := [32]byte{}
	copy(key[:], pattern(0x20, 32))
	iv := [16]byte{}
	copy(iv[:], pattern(0x40, 16))
	lengths := []int{0, 16, 32, 100}
	var vecs []streamVector
	for _, n := range lengths {
		s := crypto.NewStream(&key, &iv)
		dst := make([]byte, n)
		s.KeyStream(dst)
		vecs = append(vecs, streamVector{
			Name: fmt.Sprintf("len_%d", n), KeyHex: hx(key[:]), IvHex: hx(iv[:]),
			Length: n, KeystreamHex: hx(dst),
		})
	}
	writeVectorFile("core/sphinx/testvectors/primitives/stream_aes256ctr.json",
		"stream_aes256ctr",
		"AES-256-CTR keystream as used by Sphinx's header/routing-info encryption (crypto.NewStream), raw keystream bytes (crypto.Stream.KeyStream).",
		vecs)
}

// --- SPRP (AEZ v5, tau=0 pure-SPRP mode, Sphinx's wide-block onion cipher) ---

type sprpVector struct {
	Name          string `json:"name"`
	KeyHex        string `json:"key_hex"`
	IvHex         string `json:"iv_hex"`
	PlaintextHex  string `json:"plaintext_hex"`
	CiphertextHex string `json:"ciphertext_hex"`
}

func genSPRP() {
	key := [48]byte{}
	copy(key[:], pattern(0x60, 48))
	iv := [16]byte{}
	copy(iv[:], pattern(0x90, 16))
	// Lengths chosen to exercise both aez.git's aezTiny (< 32 bytes) and
	// aezCore (>= 32 bytes) code paths.
	lengths := []int{0, 1, 15, 16, 17, 31, 32, 33, 48, 64, 100, 1024}
	var vecs []sprpVector
	for _, n := range lengths {
		pt := pattern(byte(n), n)
		ct := crypto.SPRPEncrypt(&key, &iv, pt)
		vecs = append(vecs, sprpVector{
			Name: fmt.Sprintf("len_%d", n), KeyHex: hx(key[:]), IvHex: hx(iv[:]),
			PlaintextHex: hx(pt), CiphertextHex: hx(ct),
		})
	}
	writeVectorFile("core/sphinx/testvectors/primitives/sprp_aez.json",
		"sprp_aez",
		"AEZ v5 in Sphinx's exact usage: tau=0 (pure length-preserving SPRP, no AEZ-native auth tag), nil additional data, 48-byte key, 16-byte nonce (crypto.SPRPEncrypt). Lengths cover both aez.git's aezTiny (<32B) and aezCore (>=32B) code paths.",
		vecs)
}

// --- KDF (HKDF-SHA256 Expand-only, Sphinx's PacketKeys derivation) ---

type kdfVector struct {
	Name                  string `json:"name"`
	IkmHex                string `json:"ikm_hex"`
	HeaderMacHex          string `json:"header_mac_hex"`
	HeaderEncryptionHex   string `json:"header_encryption_hex"`
	HeaderEncryptionIvHex string `json:"header_encryption_iv_hex"`
	PayloadEncryptionHex  string `json:"payload_encryption_hex"`
	BlindingFactorSeedHex string `json:"blinding_factor_seed_hex"`
}

// kdfInfo mirrors the unexported kdfInfo in internal/crypto/crypto.go
// (kept in sync manually; there is no exported accessor).
var kdfInfo = []byte("katzenpost-kdf-v0-hkdf-sha256")

func genKDF() {
	// Reproduces internal/crypto.KDF's exact HKDF-Expand-only construction
	// directly (rather than calling the unexported machinery), so every
	// slice -- including the raw 32-byte seed that would otherwise only be
	// consumed internally by scheme.GeneratePrivateKey -- is observable.
	// This is the same public golang.org/x/crypto/hkdf API internal/crypto
	// itself calls; nothing about the construction is being reimplemented.
	const (
		macKeyLen    = crypto.MACKeyLength
		streamKeyLen = crypto.StreamKeyLength
		streamIvLen  = crypto.StreamIVLength
		sprpKeyLen   = crypto.SPRPKeyLength
		seedLen      = 32
		okmLen       = macKeyLen + streamKeyLen + streamIvLen + sprpKeyLen + seedLen
	)
	ikms := map[string][]byte{
		"32B_shared_secret_0x00": pattern(0x00, 32),
		"32B_shared_secret_0x01": pattern(0x01, 32),
	}
	names := []string{"32B_shared_secret_0x00", "32B_shared_secret_0x01"}
	var vecs []kdfVector
	for _, name := range names {
		ikm := ikms[name]
		h := hkdf.Expand(sha256.New, ikm, kdfInfo)
		okm := make([]byte, okmLen)
		if _, err := h.Read(okm); err != nil {
			panic(err)
		}
		ptr := okm
		headerMAC := ptr[:macKeyLen]
		ptr = ptr[macKeyLen:]
		headerEnc := ptr[:streamKeyLen]
		ptr = ptr[streamKeyLen:]
		headerEncIV := ptr[:streamIvLen]
		ptr = ptr[streamIvLen:]
		payloadEnc := ptr[:sprpKeyLen]
		ptr = ptr[sprpKeyLen:]
		seed := ptr[:seedLen]
		vecs = append(vecs, kdfVector{
			Name: name, IkmHex: hx(ikm),
			HeaderMacHex: hx(headerMAC), HeaderEncryptionHex: hx(headerEnc),
			HeaderEncryptionIvHex: hx(headerEncIV), PayloadEncryptionHex: hx(payloadEnc),
			BlindingFactorSeedHex: hx(seed),
		})
	}
	writeVectorFile("core/sphinx/testvectors/primitives/kdf_sphinx.json",
		"kdf_sphinx",
		"Sphinx's PacketKeys derivation: HKDF-SHA256 Expand-only (raw ikm treated directly as PRK, no Extract step) with info=\"katzenpost-kdf-v0-hkdf-sha256\", 160 bytes OKM sliced into HeaderMAC(32)+HeaderEncryption(32)+HeaderEncryptionIV(16)+PayloadEncryption(48)+BlindingFactorSeed(32). BlindingFactorSeedHex is the raw seed bytes only -- turning it into a NIKE private key is NIKE.privateKeyFromSeed's job (tested separately), not KDF's.",
		vecs)
}

func main() {
	genHash()
	genMAC()
	genStream()
	genSPRP()
	genKDF()
}
