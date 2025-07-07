package ctidh512

import (
	"fmt"
)

var (
	// ErrBlindDataSizeInvalid indicates that the blinding data size was invalid.
	ErrBlindDataSizeInvalid error = fmt.Errorf("%s: blinding data size invalid", Name())

	// ErrPublicKeyValidation indicates a public key validation failure.
	ErrPublicKeyValidation error = fmt.Errorf("%s: public key validation failure", Name())

	// ErrPublicKeySize indicates the raw data is not the correct size for a public key.
	ErrPublicKeySize error = fmt.Errorf("%s: raw public key data size is wrong", Name())

	// ErrPrivateKeySize indicates the raw data is not the correct size for a private key.
	ErrPrivateKeySize error = fmt.Errorf("%s: raw private key data size is wrong", Name())

	// ErrCTIDH indicates a group action failure.
	ErrCTIDH error = fmt.Errorf("%s: group action failure", Name())
)
