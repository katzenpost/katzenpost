//go:build !amd64 && !arm64

package csidh

import "github.com/katzenpost/hpqc/nike"

var NOBS_CSIDH512Scheme nike.Scheme = nil
