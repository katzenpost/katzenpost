package pkiclient

import (
	"context"
	"errors"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/pki"
	"testing"
	"time"
)

var (
	errNotImplemented = errors.New("Not Implemented")
)

type mockPKI struct {
}

func (m mockPKI) Post(ctx context.Context, epoch uint64, signingKey *eddsa.PrivateKey, d *pki.MixDescriptor) error {
	return errNotImplemented
}

func (m mockPKI) Get(ctx context.Context, epoch uint64) (*pki.Document, []byte, error) {
	return nil, nil, errNotImplemented
}

func (m mockPKI) Deserialize(raw []byte) (*pki.Document, error) {
	return nil, errNotImplemented
}

func TestPKIClient(t *testing.T) {
	c := New(mockPKI{})
	c.Go(c.worker)
	c.Halt()
	ctx, _ := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
	pass := make(chan bool)
	go func() {
		_, _, err := c.Get(ctx, 1234)
		switch err {
		case errHalted:
			pass <- true
		default:
		}
	}()
	select {
	case <-ctx.Done():
		t.FailNow()
	case <-pass:
	}
}
