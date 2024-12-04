package commands

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPostDescriptor(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := &PostDescriptor{
		Epoch:   0xdeadbabecafebeef,
		Payload: []byte("This is my descriptor."),
	}
	b := cmd.ToBytes()
	require.Equal(postDescriptorLength+len(cmd.Payload)+cmdOverhead, len(b), "PostDescriptor: ToBytes() length")

	cmds := NewPKICommands(testCertScheme)

	c, err := cmds.FromBytes(b)
	require.NoError(err, "PostDescriptor: FromBytes() failed")
	require.IsType(cmd, c, "PostDescriptor: FromBytes() invalid type")
	d := c.(*PostDescriptor)
	require.Equal(d.Epoch, cmd.Epoch)
	require.Equal(d.Payload, cmd.Payload)
}

func TestPostDescriptorStatus(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := &PostDescriptorStatus{
		ErrorCode: 23,
	}
	b := cmd.ToBytes()
	require.Len(b, postDescriptorStatusLength+cmdOverhead, "PostDescriptorStatus: ToBytes() length")

	cmds := NewPKICommands(testCertScheme)

	c, err := cmds.FromBytes(b)
	require.NoError(err, "PostDescriptorStatus: FromBytes() failed")
	require.IsType(cmd, c, "PostDescriptorStatus: FromBytes() invalid type")
	d := c.(*PostDescriptorStatus)
	require.Equal(d.ErrorCode, cmd.ErrorCode)
}

func TestGetVote(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	alicePub, _, err := testCertScheme.GenerateKey()
	require.NoError(err)

	cmd := &GetVote{
		Epoch:     123,
		PublicKey: alicePub,
	}
	b := cmd.ToBytes()
	require.Equal(voteOverhead(testCertScheme)+cmdOverhead, len(b), "GetVote: ToBytes() length")

	cmds := NewPKICommands(testCertScheme)

	c, err := cmds.FromBytes(b)
	require.NoError(err, "GetVote: FromBytes() failed")
	require.IsType(cmd, c, "GetVote: FromBytes() invalid type")
}

func TestVote(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	alicePub, _, err := testCertScheme.GenerateKey()
	require.NoError(err)
	cmd := &Vote{
		Epoch:     3141,
		PublicKey: alicePub,
		Payload:   []byte{1, 2, 3, 4},
	}
	b := cmd.ToBytes()
	require.Len(b, cmdOverhead+voteOverhead(testCertScheme)+len(cmd.Payload), "Vote: ToBytes() length")

	cmds := NewPKICommands(testCertScheme)

	c, err := cmds.FromBytes(b)
	require.NoError(err, "Vote: FromBytes() failed")
	require.IsType(cmd, c, "Vote: FromBytes() invalid type")
	d := c.(*Vote)
	require.Equal(d.Epoch, cmd.Epoch)

	blob1, err := d.PublicKey.MarshalBinary()
	require.NoError(err)
	blob2, err := cmd.PublicKey.MarshalBinary()
	require.NoError(err)
	require.Equal(blob1, blob2)
	require.Equal(d.Payload, cmd.Payload)
}

func TestVoteStatus(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := &VoteStatus{
		ErrorCode: 23,
	}
	b := cmd.ToBytes()
	require.Len(b, voteStatusLength+cmdOverhead, "VoteStatus: ToBytes() length")

	cmds := NewPKICommands(testCertScheme)

	c, err := cmds.FromBytes(b)
	require.NoError(err, "VoteStatus: FromBytes() failed")
	require.IsType(cmd, c, "VoteStatus: FromBytes() invalid type")
	d := c.(*VoteStatus)
	require.Equal(d.ErrorCode, cmd.ErrorCode)
}

func TestReveal(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	alicePub, _, err := testCertScheme.GenerateKey()
	require.NoError(err)
	digest := make([]byte, 32)
	for i := 0; i < 32; i++ {
		digest[i] = uint8(i)
	}
	cmd := &Reveal{
		Epoch:     3141,
		PublicKey: alicePub,
		Payload:   digest,
	}
	b := cmd.ToBytes()
	require.Len(b, cmdOverhead+revealOverhead(testCertScheme)+32, "Reveal: ToBytes() length")

	cmds := NewPKICommands(testCertScheme)

	c, err := cmds.FromBytes(b)
	require.NoError(err, "Reveal: FromBytes() failed")
	require.IsType(cmd, c, "Reveal: FromBytes() invalid type")
	d := c.(*Reveal)
	require.Equal(d.Epoch, cmd.Epoch)

	blob1, err := d.PublicKey.MarshalBinary()
	require.NoError(err)
	blob2, err := cmd.PublicKey.MarshalBinary()
	require.NoError(err)
	require.Equal(blob1, blob2)

	require.Equal(d.Payload, cmd.Payload)
}

func TestRevealtatus(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := &RevealStatus{
		ErrorCode: 23,
	}
	b := cmd.ToBytes()
	require.Len(b, revealStatusLength+cmdOverhead, "RevealStatus: ToBytes() length")

	cmds := NewPKICommands(testCertScheme)

	c, err := cmds.FromBytes(b)
	require.NoError(err, "RevealStatus: FromBytes() failed")
	require.IsType(cmd, c, "RevealStatus: FromBytes() invalid type")
	d := c.(*RevealStatus)
	require.Equal(d.ErrorCode, cmd.ErrorCode)
}

func TestCert(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	alicePub, _, err := testCertScheme.GenerateKey()
	require.NoError(err)

	cmd := &Cert{
		Epoch:     3141,
		PublicKey: alicePub,
		Payload:   []byte{1, 2, 3, 4},
	}
	b := cmd.ToBytes()
	require.Len(b, cmdOverhead+certOverhead(testCertScheme)+len(cmd.Payload), "Cert: ToBytes() length")

	cmds := NewPKICommands(testCertScheme)

	c, err := cmds.FromBytes(b)
	require.NoError(err, "Reveal: FromBytes() failed")
	require.IsType(cmd, c, "Reveal: FromBytes() invalid type")
	d := c.(*Cert)
	require.Equal(d.Epoch, cmd.Epoch)

	blob1, err := d.PublicKey.MarshalBinary()
	require.NoError(err)
	blob2, err := cmd.PublicKey.MarshalBinary()
	require.NoError(err)
	require.Equal(blob1, blob2)

	require.Equal(d.Payload, cmd.Payload)
}

func TestCertStatus(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := &CertStatus{
		ErrorCode: 14,
	}
	b := cmd.ToBytes()
	require.Len(b, certStatusLength+cmdOverhead, "CertStatus: ToBytes() length")

	cmds := NewPKICommands(testCertScheme)

	c, err := cmds.FromBytes(b)
	require.NoError(err, "CertStatus: FromBytes() failed")
	require.IsType(cmd, c, "CertStatus: FromBytes() invalid type")
	d := c.(*CertStatus)
	require.Equal(d.ErrorCode, cmd.ErrorCode)
}

func TestSig(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	alicePub, _, err := testCertScheme.GenerateKey()
	require.NoError(err)

	cmd := &Sig{
		Epoch:     3141,
		PublicKey: alicePub,
		Payload:   []byte{1, 2, 3, 4},
	}
	b := cmd.ToBytes()
	require.Len(b, cmdOverhead+sigOverhead(testCertScheme)+len(cmd.Payload), "Sig: ToBytes() length")

	cmds := NewPKICommands(testCertScheme)

	c, err := cmds.FromBytes(b)
	require.NoError(err, "Sig: FromBytes() failed")
	require.IsType(cmd, c, "Sig: FromBytes() invalid type")
	d := c.(*Sig)
	require.Equal(d.Epoch, cmd.Epoch)

	blob1, err := d.PublicKey.MarshalBinary()
	require.NoError(err)
	blob2, err := cmd.PublicKey.MarshalBinary()
	require.NoError(err)
	require.Equal(blob1, blob2)

	require.Equal(d.Payload, cmd.Payload)
}

func TestSigStatus(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmd := &SigStatus{
		ErrorCode: 23,
	}
	b := cmd.ToBytes()
	require.Len(b, revealStatusLength+cmdOverhead, "SigStatus: ToBytes() length")

	cmds := NewPKICommands(testCertScheme)

	c, err := cmds.FromBytes(b)
	require.NoError(err, "SigStatus: FromBytes() failed")
	require.IsType(cmd, c, "SigStatus: FromBytes() invalid type")
	d := c.(*SigStatus)
	require.Equal(d.ErrorCode, cmd.ErrorCode)
}
