// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"crypto/tls"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type Options struct {
	ALPN              string
	CurvePreferences  []string
	AddressValidation string
	KeepAlivePeriod   *time.Duration
	KeepAliveJitter   *float64
}

func (o *Options) Validate() error {
	return nil
}

func (o *Options) nextProtos() []string {
	return []string{http3.NextProtoH3}
}

func (o *Options) curvePreferences() []tls.CurveID {
	return nil
}

func (o *Options) quicConfig() *quic.Config {
	return Config()
}
