package commands

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/mkem"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func TestReplicaMessageReplyWithoutPadding(t *testing.T) {
	t.Parallel()

	envelopeHash := &[32]byte{}
	_, err := rand.Reader.Read(envelopeHash[:])
	require.NoError(t, err)

	reply1 := ReplicaMessageReply{
		ErrorCode:     0xAA,
		EnvelopeHash:  envelopeHash,
		ReplicaID:     123,
		EnvelopeReply: []byte("hello world"),
	}

	blob1 := reply1.ToBytes()
	reply2raw, err := replicaMessageReplyFromBytes(blob1[cmdOverhead:], nil)
	require.NoError(t, err)
	reply2 := reply2raw.(*ReplicaMessageReply)

	require.Equal(t, reply1.ErrorCode, reply2.ErrorCode)
	require.Equal(t, reply1.EnvelopeHash[:], reply2.EnvelopeHash[:])
	require.Equal(t, reply1.ReplicaID, reply2.ReplicaID)
	require.Equal(t, reply1.EnvelopeReply, reply2.EnvelopeReply)

	blob2 := reply2.ToBytes()
	require.Equal(t, blob1, blob2)
}

func TestReplicaMessageReplyWithPadding(t *testing.T) {
	t.Parallel()

	nike := ecdh.Scheme(rand.Reader)
	forwardPayloadLength := 1234
	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)

	cmds := NewStorageReplicaCommands(s.Geometry(), nike)

	envelopeHash := &[32]byte{}
	_, err := rand.Reader.Read(envelopeHash[:])
	require.NoError(t, err)

	reply1 := ReplicaMessageReply{
		Cmds:          cmds,
		ErrorCode:     1,
		EnvelopeHash:  envelopeHash,
		ReplicaID:     123,
		EnvelopeReply: []byte("hello world"),
	}

	blob1 := reply1.ToBytes()

	reply2raw, err := cmds.FromBytes(blob1)
	require.NoError(t, err)
	reply2 := reply2raw.(*ReplicaMessageReply)

	require.Equal(t, reply1.ErrorCode, reply2.ErrorCode)
	require.Equal(t, reply1.EnvelopeHash[:], reply2.EnvelopeHash[:])
	require.Equal(t, reply1.ReplicaID, reply2.ReplicaID)
	require.Equal(t, reply1.EnvelopeReply, reply2.EnvelopeReply)

	blob2 := reply2.ToBytes()
	require.Equal(t, blob1, blob2)
}

func TestReplicaMessage(t *testing.T) {
	t.Parallel()
	const payload = "A free man must be able to endure it when his fellow men act and live otherwise than he considers proper. He must free himself from the habit, just as soon as something does not please him, of calling for the police."

	nike := ecdh.Scheme(rand.Reader)
	forwardPayloadLength := 1234
	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)

	cmds := NewStorageReplicaCommands(s.Geometry(), nike)

	senderKey := make([]byte, HybridKeySize(nike))
	_, err := rand.Reader.Read(senderKey[:])
	require.NoError(t, err)

	dek := &[mkem.DEKSize]byte{}
	_, err = rand.Reader.Read(dek[:])
	require.NoError(t, err)

	replicaMessage1 := &ReplicaMessage{
		Geo:    geo,
		Cmds:   cmds,
		Scheme: nike,

		SenderEPubKey: senderKey,
		DEK:           dek,
		Ciphertext:    []byte(payload),
	}
	blob := replicaMessage1.ToBytes()

	replicaMessage2, err := cmds.FromBytes(blob)
	require.NoError(t, err)

	require.Equal(t, replicaMessage1.DEK[:], replicaMessage2.(*ReplicaMessage).DEK[:])
}

func TestReplicaWrite(t *testing.T) {
	t.Parallel()
	const payload = "A free man must be able to endure it when his fellow men act and live otherwise than he considers proper. He must free himself from the habit, just as soon as something does not please him, of calling for the police."

	nike := ecdh.Scheme(rand.Reader)
	forwardPayloadLength := 1234
	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)

	cmds := NewStorageReplicaCommands(s.Geometry(), nike)
	id := &[32]byte{}
	_, err := rand.Reader.Read(id[:])
	require.NoError(t, err)

	signature := &[64]byte{}
	_, err = rand.Reader.Read(signature[:])
	require.NoError(t, err)

	readCmd := &ReplicaWrite{
		Cmds: cmds,

		BoxID:     id,
		Signature: signature,
		Payload:   []byte(payload),
	}

	blob1 := readCmd.ToBytes()
	readCmd2, err := cmds.FromBytes(blob1)
	require.NoError(t, err)
	require.Equal(t, readCmd2.(*ReplicaWrite).BoxID[:], readCmd.BoxID[:])
	require.Equal(t, readCmd2.(*ReplicaWrite).Signature[:], readCmd.Signature[:])
	require.Equal(t, readCmd2.(*ReplicaWrite).Payload, readCmd.Payload)

	blob2 := readCmd2.ToBytes()
	require.Equal(t, blob1, blob2)
}

func TestReplicaWriteWithoutPadding(t *testing.T) {
	t.Parallel()
	const payload = "A free man must be able to endure it when his fellow men act and live otherwise than he considers proper. He must free himself from the habit, just as soon as something does not please him, of calling for the police."

	id := &[32]byte{}
	_, err := rand.Reader.Read(id[:])
	require.NoError(t, err)

	signature := &[64]byte{}
	_, err = rand.Reader.Read(signature[:])
	require.NoError(t, err)

	writeCmd := &ReplicaWrite{
		Cmds:      nil,
		BoxID:     id,
		Signature: signature,
		Payload:   []byte(payload),
	}

	blob1 := writeCmd.ToBytes()
	writeCmd2, err := replicaWriteFromBytes(blob1[cmdOverhead:], nil)
	require.NoError(t, err)

	require.Equal(t, writeCmd2.(*ReplicaWrite).BoxID[:], writeCmd.BoxID[:])
	require.Equal(t, writeCmd2.(*ReplicaWrite).Signature[:], writeCmd.Signature[:])
	require.Equal(t, writeCmd2.(*ReplicaWrite).Payload, writeCmd.Payload)

	blob2 := writeCmd2.ToBytes()
	require.Equal(t, blob1, blob2)
}

func TestReplicaWriteReply(t *testing.T) {
	t.Parallel()
	const payload = "A free man must be able to endure it when his fellow men act and live otherwise than he considers proper. He must free himself from the habit, just as soon as something does not please him, of calling for the police."

	nike := ecdh.Scheme(rand.Reader)
	forwardPayloadLength := 1234
	nrHops := 5

	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	cmds := NewStorageReplicaCommands(geo, nike)
	id := &[32]byte{}
	_, err := rand.Reader.Read(id[:])
	require.NoError(t, err)

	writeCmd := &ReplicaWriteReply{
		Cmds: cmds,

		ErrorCode: 123,
	}

	blob1 := writeCmd.ToBytes()
	writeCmd2, err := cmds.FromBytes(blob1)
	require.NoError(t, err)
	require.Equal(t, writeCmd2.(*ReplicaWriteReply).ErrorCode, writeCmd.ErrorCode)

	blob2 := writeCmd2.ToBytes()
	require.Equal(t, blob1, blob2)

}

func TestPostReplicaDescriptor(t *testing.T) {
	pkiSignatureScheme := schemes.ByName("ed25519")
	cmds := NewPKICommands(pkiSignatureScheme)

	d := PostReplicaDescriptor{
		Epoch:   123,
		Payload: []byte("hello"),
	}
	blob := d.ToBytes()

	rawcmd, err := cmds.FromBytes(blob)
	require.NoError(t, err)
	cmd := rawcmd.(*PostReplicaDescriptor)

	require.Equal(t, d.Epoch, cmd.Epoch)
	require.Equal(t, d.Payload, cmd.Payload)
}
