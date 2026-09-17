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

## 2. bacap StatefulReader from crafted bytes panics in ed25519.Blind  [fixed in hpqc v0.0.88]

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

Root cause was in hpqc v0.0.87: NewStatefulReaderFromBytes did not validate the
embedded ed25519 public key, so a crafted ReadCap yielded a reader that panicked
on first use. This is the same crafted-cap DoS class as the courier WriteCap
crash. Fixed in hpqc v0.0.88 (PR #120): ed25519.PublicKey.Blind and the bacap
box-ID derivations (BoxIDForContext, DeriveBoxID) now return an error instead of
panicking on a degenerate or uninitialized key. Confirmed against v0.0.88 -- the
target now runs millions of execs without a crash.

## 3. SendRetrievePacket accepts a wrong-length Sphinx packet  [fixed here]

Target: FuzzMixnetCommandsFromBytes (fuzzing-kit, core/wire/commands/).
sendRetrievePacketFromBytes (core/wire/commands/commands.go) copies every
remaining byte into SphinxPacket without checking len == geo.PacketLength, so a
peer's SendRetrievePacket with a wrong-length body is accepted; SendRetrievePacket.ToBytes
then panics "SphinxPacket must be set to Geo.PacketLength". Fix: reject
len(b) != cmds.geo.PacketLength in sendRetrievePacketFromBytes.

## 4. Consensus2 parsed by FromBytes is not re-encodable  [low, harness]

Target: FuzzPKICommandsFromBytes (fuzzing-kit, core/wire/commands/).
consensus2FromBytes does not set the Cmds back-reference (it has no access to
it), so Consensus2.ToBytes nil-derefs on c.Cmds.padToMaxCommandSize. A received
Consensus2 is read for its payload and never re-encoded in production, so this
is a decode/encode asymmetry the round-trip check surfaced, not a network DoS.
Either hand the decoder the Commands set, or relax the fuzz target round-trip
for decode-only commands.

## 5. hybrid signature UnmarshalBinaryPublicKey/PrivateKey slice panic  [fixed in hpqc v0.0.88]

Target: FuzzSignUntrustedInput (fuzzing-kit, hpqcfuzz/). Against hpqc v0.0.87,
sign/hybrid UnmarshalBinaryPublicKey/PrivateKey sliced b[:first.PublicKeySize()]
without a length check, so a short input panicked (slice out of range). Every
hybrid signature scheme shared it, including the dirauth default Ed25519 Sphincs+,
so it was reachable wherever a hybrid public or private key is unmarshaled from the
wire. Fixed in hpqc v0.0.88 (PR #118), which adds a len(b) != Size() guard.
Confirmed against v0.0.88 -- the target now runs millions of execs without a crash.
