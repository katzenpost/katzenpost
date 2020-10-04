package ratchet

import (
	"time"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	keySize        = 32
	privateKeySize = 32
	publicKeySize  = 32
	signatureSize  = 64

	sharedKeySize         = 32
	rootKeySize           = 32
	chainKeySize          = 32
	sendingChainKeySize   = 32
	receivingChainKeySize = 32
	messageKeySize        = 32
	nonceSize             = 24
	// headerSize is the size, in bytes, of a header's plaintext contents.
	headerSize = 4 /* uint32 message count */ +
		4 /* uint32 previous message count */ +
		32 /* curve25519 ratchet public */ +
		24 /* nonce for message */
	// sealedHeader is the size, in bytes, of an encrypted header.
	sealedHeaderSize = 24 /* nonce */ + headerSize + secretbox.Overhead
	// nonceInHeaderOffset is the offset of the message nonce in the
	// header's plaintext.
	nonceInHeaderOffset = 4 + 4 + 32
	// MaxMissingMessages is the maximum number of missing messages that
	// we'll keep track of.
	MaxMissingMessages = 8

	// RatchetKeyMaxLifetime is the maximum lifetime of the ratchet
	RatchetKeyMaxLifetime = time.Hour * 672

	// DoubleRatchetOverhead is the number of bytes the ratchet adds in ciphertext overhead.
	DoubleRatchetOverhead = 120
)
