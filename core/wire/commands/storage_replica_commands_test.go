package commands

import (
	"testing"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

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

	dek := &[32]byte{}
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

	signature := &[32]byte{}
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

	blob2 := readCmd2.ToBytes()
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

	readCmd := &ReplicaWriteReply{
		Cmds: cmds,

		ErrorCode: 123,
	}

	blob1 := readCmd.ToBytes()
	readCmd2, err := cmds.FromBytes(blob1)
	require.NoError(t, err)
	require.Equal(t, readCmd2.(*ReplicaWriteReply).ErrorCode, readCmd.ErrorCode)

	blob2 := readCmd2.ToBytes()
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
