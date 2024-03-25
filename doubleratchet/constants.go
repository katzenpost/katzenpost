package ratchet

import (
	"time"

	"github.com/henrydcase/nobs/dh/csidh"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	keySize               = 32
	rootKeySize           = 32
	chainKeySize          = 32
	sendingChainKeySize   = 32
	receivingChainKeySize = 32
	messageKeySize        = 32
	nonceSize             = 24
	// headerSize is the size, in bytes, of a header's plaintext contents.
	headerSize = 4 /* uint32 message count */ +
		4 /* uint32 previous message count */ +
		24 /* nonce for message */ +
		32 + 128 /* ratchet public key CTIDH-1024 + X25519 */
	// sealedHeader is the size, in bytes, of an encrypted header.
	sealedHeaderSize               = 24 /* nonce */ + headerSize + secretbox.Overhead
	RatchetPublicKeyInHeaderOffset = 4 + 4 + 24
	// nonceInHeaderOffset is the offset of the message nonce in the
	// header's plaintext.
	nonceInHeaderOffset = 4 + 4
	// MaxMissingMessages is the maximum number of missing messages that
	// we'll keep track of.
	MaxMissingMessages = 8

	// RatchetKeyMaxLifetime is the maximum lifetime of the ratchet
	RatchetKeyMaxLifetime = time.Hour * 672

	// DoubleRatchetOverhead is the number of bytes the ratchet adds in ciphertext overhead.
	DoubleRatchetOverhead = 120 + csidh.PublicKeySize
)
