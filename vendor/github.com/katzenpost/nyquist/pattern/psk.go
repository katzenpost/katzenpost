// Copyright (C) 2019, 2021 Yawning Angel. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package pattern

import (
	"errors"
	"strconv"
	"strings"
)

const prefixPSK = "psk"

// MakePSK applies `psk` modifiers to an existing pattern, returning the new
// pattern.
func MakePSK(template Pattern, modifier string) (Pattern, error) {
	if template.NumPSKs() > 0 {
		return nil, errors.New("nyquist/pattern: PSK template pattern already has PSKs")
	}

	pa := &builtIn{
		name:        template.String() + modifier,
		preMessages: template.PreMessages(),
		isOneWay:    template.IsOneWay(),
	}

	// Deep-copy the messages.
	templateMessages := template.Messages()
	pa.messages = make([]Message, 0, len(templateMessages))
	for _, v := range templateMessages {
		pa.messages = append(pa.messages, append(Message{}, v...))
	}

	// Apply the psk modifiers to all of the patterns.
	indexes := make(map[int]bool)
	splitModifier := strings.Split(modifier, "+")
	for _, v := range splitModifier {
		if !strings.HasPrefix(v, prefixPSK) {
			return nil, errors.New("nyquist/pattern: non-PSK modifier: " + v)
		}
		v = strings.TrimPrefix(v, prefixPSK)
		pskIndex, err := strconv.Atoi(v)
		if err != nil {
			return nil, errors.New("nyquist/pattern: failed to parse PSK index: " + err.Error())
		}

		if indexes[pskIndex] {
			return nil, errors.New("nyquist/pattern: redundant PSK modifier: " + prefixPSK + v)
		}
		if pskIndex < 0 || pskIndex > len(templateMessages) {
			return nil, errors.New("nyquist/pattern: invalid PSK modifier: " + prefixPSK + v)
		}
		switch pskIndex {
		case 0:
			pa.messages[0] = append(Message{Token_psk}, pa.messages[0]...)
		default:
			idx := pskIndex - 1
			pa.messages[idx] = append(pa.messages[idx], Token_psk)
		}
		indexes[pskIndex] = true
	}
	pa.numPSKs = len(indexes)

	return pa, nil
}

func mustMakePSK(template Pattern, modifier string) Pattern {
	pa, err := MakePSK(template, modifier)
	if err != nil {
		panic(err)
	}
	return pa
}
