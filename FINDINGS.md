# Fuzzing findings

Bugs surfaced by the fuzzing kit (see the fuzzing-kit branch). Fixes that live
in katzenpost are committed here; a fix that lives in a dependency is recorded
with its reproducer.

## 1. pkicache.New panics on an empty topology  [fixed here]

appendMap indexed doc.Topology by a layer byte with no bounds check, and
incomingLayer/outgoingLayer compute uint8(len(Topology))-1, which underflows to
255 on an empty topology. Fixed with a bounds guard. Gated behind
IsDocumentWellFormed today, so not network-reachable, but New must not panic
regardless of caller.

## 2. bacap StatefulReader from crafted bytes panics in ed25519.Blind  [hpqc]

Target: FuzzStatefulReaderFromBytesNextBoxID (fuzzing-kit, bacap/).
Reproducer input:

    go test fuzz v1
    []byte("\xf6")

NewStatefulReaderFromBytes accepts these bytes with a nil error, then NextBoxID
panics:

    panic: k.Bytes() was not a valid [32]byte slice public key. Was *PublicKey initialized?
    hpqc/sign/ed25519.(*PublicKey).Blind         blinded25519.go:317
    hpqc/bacap.(*MessageBoxIndex).BoxIDForContext bacap_impl.go:111
    hpqc/bacap.(*StatefulReader).NextBoxID        bacap_impl.go:572

Root cause is in hpqc v0.0.87: NewStatefulReaderFromBytes does not validate the
embedded ed25519 public key, so a crafted ReadCap yields a reader that panics
on first use. This is the same crafted-cap DoS class as the courier WriteCap
crash. The fix belongs in hpqc: reject an invalid or uninitialized key in
NewStatefulReaderFromBytes, or make ed25519.Blind return an error rather than
panic. Add the reproducer as a bacap regression once hpqc is fixed.
