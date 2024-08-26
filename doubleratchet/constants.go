package ratchet

import (
	"time"
)

const (
	keySize                        = 32
	rootKeySize                    = 32
	chainKeySize                   = 32
	sendingChainKeySize            = 32
	receivingChainKeySize          = 32
	messageKeySize                 = 32
	nonceSize                      = 24
	RatchetPublicKeyInHeaderOffset = 4 + 4
	// MaxMissingMessages is the maximum number of missing messages that
	// we'll keep track of.
	MaxMissingMessages = 8

	// RatchetKeyMaxLifetime is the maximum lifetime of the ratchet
	RatchetKeyMaxLifetime = time.Hour * 672

	// doubleRatchetOverheadSansPubKey is the number of bytes the ratchet adds in ciphertext overhead without nike.PublicKeySize
	doubleRatchetOverheadSansPubKey = 88
)
