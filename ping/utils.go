package main

import (
	"fmt"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

func randUser() string {
	user := [32]byte{}
	_, err := rand.Reader.Read(user[:])
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", user[:])
}
