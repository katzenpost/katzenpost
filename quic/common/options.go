// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

type Options struct {
	ALPN              string
	CurvePreferences  []string
	AddressValidation string
	KeepAlivePeriod   *time.Duration
	KeepAliveJitter   *float64
	PinMismatch       string
	CloseLinger       time.Duration
	Signature         string

	client bool
}

func (o *Options) ForClient() *Options {
	c := Options{}
	if o != nil {
		c = *o
	}
	c.client = true
	return &c
}

const (
	AddressValidationAlways    = "always"
	AddressValidationUnderLoad = "under-load"
	AddressValidationOff       = "off"
)

const (
	PinMismatchFallback = "fallback"
	PinMismatchStrict   = "strict"
)

var knownCurves = []tls.CurveID{
	tls.X25519,
	tls.X25519MLKEM768,
	tls.SecP256r1MLKEM768,
	tls.SecP384r1MLKEM1024,
	tls.CurveP256,
	tls.CurveP384,
	tls.CurveP521,
}

func curveByName(name string) (tls.CurveID, bool) {
	i := slices.IndexFunc(knownCurves, func(c tls.CurveID) bool { return c.String() == name })
	if i < 0 {
		return 0, false
	}
	return knownCurves[i], true
}

func (o *Options) Validate() error {
	if o == nil {
		return nil
	}
	if len(o.ALPN) > 255 {
		return errors.New("quic: ALPN is longer than 255 bytes")
	}
	for i, name := range o.CurvePreferences {
		if _, ok := curveByName(name); !ok {
			return fmt.Errorf("quic: unknown curve %q in CurvePreferences", name)
		}
		if slices.Contains(o.CurvePreferences[:i], name) {
			return fmt.Errorf("quic: curve %q repeats in CurvePreferences", name)
		}
	}
	switch o.AddressValidation {
	case "", AddressValidationAlways, AddressValidationUnderLoad, AddressValidationOff:
	default:
		return fmt.Errorf("quic: AddressValidation %q is not %q, %q or %q", o.AddressValidation, AddressValidationAlways, AddressValidationUnderLoad, AddressValidationOff)
	}
	switch o.PinMismatch {
	case "", PinMismatchFallback, PinMismatchStrict:
	default:
		return fmt.Errorf("quic: PinMismatch %q is not %q or %q", o.PinMismatch, PinMismatchFallback, PinMismatchStrict)
	}
	if o.KeepAlivePeriod != nil && *o.KeepAlivePeriod < 0 {
		return errors.New("quic: KeepAlivePeriod is negative")
	}
	if o.KeepAliveJitter != nil && !(*o.KeepAliveJitter >= 0 && *o.KeepAliveJitter < 1) {
		return errors.New("quic: KeepAliveJitter is outside [0, 1)")
	}
	if o.CloseLinger < 0 {
		return errors.New("quic: CloseLinger is negative")
	}
	if err := validateSignature(o.Signature); err != nil {
		return err
	}
	return nil
}

const DefaultALPN = "h3"

func (o *Options) nextProtos() []string {
	if o == nil || o.ALPN == "" {
		return []string{DefaultALPN}
	}
	return []string{o.ALPN}
}

func (o *Options) curvePreferences() []tls.CurveID {
	if o == nil {
		return nil
	}
	var curves []tls.CurveID
	for _, name := range o.CurvePreferences {
		if c, ok := curveByName(name); ok {
			curves = append(curves, c)
		}
	}
	return curves
}

const (
	ServerKeepAlivePeriod  = 45 * time.Second
	ClientKeepAlivePeriod  = 20 * time.Second
	DefaultKeepAliveJitter = 0.25
)

func (o *Options) keepAlivePeriod() time.Duration {
	period, jitter := ServerKeepAlivePeriod, DefaultKeepAliveJitter
	if o != nil && o.client {
		period = ClientKeepAlivePeriod
	}
	if o != nil && o.KeepAlivePeriod != nil {
		period = *o.KeepAlivePeriod
	}
	if o != nil && o.KeepAliveJitter != nil {
		jitter = *o.KeepAliveJitter
	}
	return time.Duration(float64(period) * (1 + jitter*(2*rand.Float64()-1)))
}

func (o *Options) closeLinger() time.Duration {
	if o == nil || o.CloseLinger == 0 {
		return closeLinger
	}
	return o.CloseLinger
}

func (o *Options) connectionConfig() *quic.Config {
	cfg := Config()
	cfg.KeepAlivePeriod = o.keepAlivePeriod()
	return cfg
}

func (o *Options) dialConfig() *quic.Config {
	cfg := o.connectionConfig()
	cfg.MaxIncomingStreams = -1
	return cfg
}

func (o *Options) quicConfig() *quic.Config {
	cfg := o.connectionConfig()
	cfg.GetConfigForClient = func(*quic.ClientInfo) (*quic.Config, error) {
		return o.connectionConfig(), nil
	}
	return cfg
}

const UnderLoadHandshakes = 128

type handshakeSettleKey struct{}

type handshakes struct {
	inFlight atomic.Int64
}

func (h *handshakes) underLoad(net.Addr) bool {
	return h.inFlight.Load() >= UnderLoadHandshakes
}

func (h *handshakes) connContext(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
	h.inFlight.Add(1)
	settle := sync.OnceFunc(func() { h.inFlight.Add(-1) })
	context.AfterFunc(ctx, settle)
	return context.WithValue(ctx, handshakeSettleKey{}, settle), nil
}

func settleHandshake(conn *quic.Conn) {
	if settle, ok := conn.Context().Value(handshakeSettleKey{}).(func()); ok {
		settle()
	}
}

func always(net.Addr) bool {
	return true
}

func (o *Options) validateAddresses(transport *quic.Transport) {
	mode := ""
	if o != nil {
		mode = o.AddressValidation
	}
	switch mode {
	case AddressValidationOff:
	case AddressValidationUnderLoad:
		h := &handshakes{}
		transport.VerifySourceAddress = h.underLoad
		transport.ConnContext = h.connContext
	default:
		transport.VerifySourceAddress = always
	}
}
