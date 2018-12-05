
Low-level client design specification document

Abstract
--------

A low level client that can be used to compose more sophisticated client libraries.


Scope
-----

There will not be any end to end cryptography present in this client
with the exception of the Sphinx packet format. However, Sphinx packets
in Katzenpost terminate at the destination Provider. Therefore the data
being transported MUST use some form of encryption. This presents several
challenges that are not solved in this library.



Message Retreival
-----------------

There are two types of message retreival that are possible and
they are:
    * retreival from local Provider, which means directly connecting to the Provider with our
       Katzenpost link layer wire protocol and sending the
       "retreive message" command to retreive messages from the
       message spool on that Provider for a given user identity.

    * retreival from remote Provider: Here we shall refer to the
    "dead drop" specification document which goes into detail how
    the remote Provider can be queried "over the mixnet".




Forward Messaging
-----------------

The client shall send forward messages in either of two modes:
    * reliable
    * unreliable

The reliable mode means the forward message is bundled with a SURB in the Sphinx payload
and this SURB is used by the destination Provider to send an ACK control message back the
originating client.


Reliable Message delivery
-------------------------
Message retransmission occurs after a timeout determined by the estimated forward+return path delays and (exponential back off?).
Message retransmissions occur N times before a permanent error is returned to the originating client (how?)

Unreliable Message delivery
---------------------------
Messages sent via the unreliable path are sent once with no guarrantees about reliability or indication if they have been delivered.
No SURBs are exposed to the recipients provider.

Quesiton: can a message payload contain a SURB? #XXX does this API provide any mechanism to attach e2e (client to client) SURBS? #XXX: this is not the mailproxy design as SURBS are not used to address recipients or reply to them.


Service queries (kaetzchen autoresponders)

Storage can persistence shall have multiple implementations:
    * cryptographic storage to disk
    * plaintext memory storage

Storage API for communications metadata.
 * Records state of messages and SURB IDs for service replies or message acknowledgements. Items persisted link a specific queries with their replies. In the case of reliable messages ... In the case of a service query

Information that is contained in the metadata storage consists of:
 * Message ID, SURB ID, status triples
 * Message indices?

Information that is NOT stored in the metadata storage and is up to the consumer of the client API to implement:
  * Contents of messages
  * Contacts of clients
  * Anything implemented by the API consumer

Implementations
 * In memory implementation. Nothing is persisted to disk, and all state is lost at program exit. No reliability guarrantees exist after a client instance is terminated.
 * On disk implementation. Message metadata is retained to disk for <duration> or until a message is acknowledged or a response is received. Upon restarting a client this metadata repository is loaded from disk.
 
API methods (subject to change)
 * Create initializes a metadata store
 * Read loads a metadata store from disk
 * Write writes a metadata store to disk
 * Destroy erases a metadata store from disk

Each store item contains one CBOR serialized structure that is deserialized into program memory at client initialization. At client graceful shutdown, state is stored to disk by serializing the in-memory structure and writing it to disk. The storage API does NOT provide journaling or fault handling in the event of a program crash. (Too bad, so sad?).

#XXX this is a regression from using a database with transactions, where a fault can be recovered after a program crash. Implementing this functionality is a lot of work though, unless we want to reuse boltdb+mailproxy's use therof.


..







* reliable delivery
  * messages in transit for longer than client is online
* mailbox registration? (registration in general)
* retreiving messages from deaddrops
* storage of state to disk















