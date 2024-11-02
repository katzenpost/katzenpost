// SPDX-FileCopyrightText: Copyright (C) 2017  David Anthony Stainton, Yawning Angel
// SPDX-License-Identifier: AGPL-3.0-only

// Wire protocol commands.
package commands

const (
	cmdOverhead = 1 + 1 + 4

	retreiveMessageLength = 4
	messageBaseLength     = 1 + 1 + 4

	getConsensusLength  = 8
	consensusBaseLength = 1

	postDescriptorStatusLength = 1
	postDescriptorLength       = 8

	certStatusLength   = 1
	revealStatusLength = 1
	sigStatusLength    = 1
	voteStatusLength   = 1

	replicaMessageReplyLength = 1
	replicaWriteReplyLength   = 1

	messageTypeMessage messageType = 0
	messageTypeACK     messageType = 1
	messageTypeEmpty   messageType = 2

	// Generic commands.
	noOp       commandID = 0
	disconnect commandID = 1

	// client2 commands
	sendRetrievePacket      commandID = 3
	sendRetrievePacketReply commandID = 4

	// used by Pigeonhole Couriers when talking to the Storage Replicas
	replicaMessage      commandID = 8
	replicaMessageReply commandID = 9

	// used by Pigeonhole Storage Replicas when talking to the PKI
	postReplicaDescriptorStatus commandID = 10
	postReplicaDescriptor       commandID = 11

	// used by Pigeonhole Storage Replicas when talking amonst themselves
	replicaWrite      commandID = 12
	replicaWriteReply commandID = 13

	// these commands are only used encapsulated within
	// replicaMessage and replicaMessageReply respectively
	replicaRead      commandID = 14
	replicaReadReply commandID = 15

	// used by old client
	retreiveMessage commandID = 16
	message         commandID = 17
	sendPacket      commandID = 2

	// client Dir-auth commands.
	getConsensus commandID = 18
	consensus    commandID = 19

	// Dir-auth commands that are only used by the dir-auth nodes.
	postDescriptor       commandID = 20
	postDescriptorStatus commandID = 21
	vote                 commandID = 22
	voteStatus           commandID = 23
	getVote              commandID = 24
	reveal               commandID = 25
	revealStatus         commandID = 26
	sig                  commandID = 27
	sigStatus            commandID = 28
	certificate          commandID = 29
	certStatus           commandID = 30

	// ConsensusOk signifies that the GetConsensus request has completed
	// successfully.
	ConsensusOk = 0

	// ConsensusNotFound signifies that the document document corresponding
	// to the epoch in the GetConsensus was not found, but retrying later
	// may be successful.
	ConsensusNotFound = 1

	// ConsensusGone signifies that the document corresponding to the epoch
	// in the GetConsensus was not found, and that retrying later will
	// not be successful.
	ConsensusGone = 2

	// DescriptorOk signifies that the PostDescriptor request has completed
	// succcessfully.
	DescriptorOk = 0

	// DescriptorInvalid signifies that the PostDescriptor request has failed
	// due to an unspecified error.
	DescriptorInvalid = 1

	// DescriptorConflict signifies that the PostDescriptor request has
	// failed due to the uploaded descriptor conflicting with a previously
	// uploaded descriptor.
	DescriptorConflict = 2

	// DescriptorForbidden signifies that the PostDescriptor request has
	// failed due to an authentication error.
	DescriptorForbidden = 3

	// VoteOk signifies that the vote was accepted by the peer.
	VoteOk = 0

	// VoteTooLate signifies that the vote was too late.
	VoteTooLate = 1

	// VoteTooEarly signifies that the vote was too late.
	VoteTooEarly = 2

	// VoteNotAuthorized signifies that the voting entity's key is not authorized.
	VoteNotAuthorized = 3

	// VoteNotSigned signifies that the vote payload failed signature verification.
	VoteNotSigned = 4

	// VoteMalformed signifies that the vote payload was invalid.
	VoteMalformed = 5

	// VoteAlreadyReceived signifies that the vote from that peer was already received.
	VoteAlreadyReceived = 6

	// VoteNotFound signifies that the vote was not found.
	VoteNotFound = 7

	// RevealOk signifies that the reveal was accepted by the peer.
	RevealOk = 8

	// RevealTooEarly signifies that the peer is breaking protocol.
	RevealTooEarly = 9

	// RevealNotAuthorized signifies that the revealing entity's key is not authorized.
	RevealNotAuthorized = 10

	// RevealNotSigned signifies that the reveal payload failed signature verification.
	RevealNotSigned = 11

	// RevealAlreadyReceived signifies that the reveal from that peer was already received.
	RevealAlreadyReceived = 12

	// RevealTooLate signifies that the reveal from that peer arrived too late.
	RevealTooLate = 13

	// CertOk signifies that the certificate was accepted by the peer.
	CertOk = 14

	// CertTooEarly signifies that the peer is breaking protocol.
	CertTooEarly = 15

	// CertNotAuthorized signifies that the certifying entity's key is not
	CertNotAuthorized = 16

	// CertNotSigned signifies that the certficiate payload failed signature verification.
	CertNotSigned = 17

	// CertAlreadyReceived signifies that the certificate from that peer was already received.
	CertAlreadyReceived = 18

	// CertTooLate signifies that the certificate from that peer arrived too late.
	CertTooLate = 19

	// SigOK signifies that the signature was accepted by the peer.
	SigOk = 20

	// SigNotAuthorized signifies that the entity's key is not authorized.
	SigNotAuthorized = 21

	// SigNotSigned signifies that the signature command failed signature verification.
	SigNotSigned = 22

	// SigTooEarly signifies that the peer is breaking protocol.
	SigTooEarly = 23

	// SigTooLate signifies that the signature from that peer arrived too late.
	SigTooLate = 24

	// SigAlreadyReceived signifies that the signature from that peer was already received.
	SigAlreadyReceived = 25

	// SigInvalid signifies that the signature failed to deserialiez.
	SigInvalid = 26
)
