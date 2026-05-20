// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonhole

import "testing"

// The trunnel-emitted gen-fuzz.go file uses the legacy //go:build gofuzz
// signature for dvyukov/go-fuzz and is not invoked by `go test -fuzz`.
// These wrappers expose the same Parse paths under the standard library
// fuzz API so they can be exercised in CI and developer workflows.
//
// Each fuzz target verifies that the corresponding Parse method does
// not panic on arbitrary input and either returns a value or an error.
// Memory-exhaustion bugs surface here too: the MaxParseSize cap will
// reject oversized inputs, and the IDRef bounds check will reject
// length-field overflows; both errors are acceptable outcomes.

func FuzzParseCourierEnvelope(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCourierEnvelope(data)
	})
}

func FuzzParseCourierEnvelopeReply(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCourierEnvelopeReply(data)
	})
}

func FuzzParseCourierQuery(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCourierQuery(data)
	})
}

func FuzzParseCourierQueryReply(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCourierQueryReply(data)
	})
}

func FuzzParseReplicaRead(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseReplicaRead(data)
	})
}

func FuzzParseReplicaReadReply(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseReplicaReadReply(data)
	})
}

func FuzzParseReplicaInnerMessage(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseReplicaInnerMessage(data)
	})
}

func FuzzParseReplicaWrite(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseReplicaWrite(data)
	})
}

func FuzzParseReplicaMessageReplyInnerMessage(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseReplicaMessageReplyInnerMessage(data)
	})
}

func FuzzParseReplicaWriteReply(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseReplicaWriteReply(data)
	})
}

func FuzzParseBox(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseBox(data)
	})
}

func FuzzParseCopyCommand(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCopyCommand(data)
	})
}

func FuzzParseCopyCommandReply(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCopyCommandReply(data)
	})
}

func FuzzParseCopyStreamElement(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCopyStreamElement(data)
	})
}
