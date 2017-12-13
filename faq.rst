
Frequently Asked Questions
==========================

1. What is a mix network?

   A mix network is an unreliable packet switching network which
   resists traffic analysis. Mix networks can be designed to provide
   properties such as sender anonymity, receiver anonymity and sender
   and receiver anonymity with respect to third party observers.

2. What is Loopix?

   Loopix is described in the paper "The Loopix Anonymity System"
   published at USENIX 2017, https://arxiv.org/pdf/1703.00536.pdf

   Briefly, Loopix uses a collection of the best mix network designs
   to create a messaging system that has the property of sender and
   receiver anonymity with respect to third party observers. Loopix
   uses the Sphinx cryptographic packet format, various kinds of decoy
   traffic and the stratified mix topology.

3. What is Katzenpost?

   Katzenpost has the goal of implementing the Loopix designs with the
   additional property of message transport reliability.

4. How are mix networks different from Tor?

   Tor is stream oriented. Mixnets are message oriented.
   Tor can be easily be deanonymized by statistical correlation attacks
   by a sufficiently global adversary whereas mixnets are not immediately
   vulnerable to these kinds of attacks if they correctly use mix strategies
   and decoy traffic.

5. How do mix networks compare to Pond?

    Pond doesn't actually mix anything whereas mix networks specifically
    contain component mixes, each containing a mix queue which "mixes"
    messages together via some specific mix strategy before sending them
    to the next hop in the route. Pond uses a group signature scheme to
    prevent the server from learning to whom a message is being sent to.
    Pond uses Tor onion services as it's transport while also using decoy
    traffic to prevent a passive network observer from determining when
    a user sends a message. Mix network designs can also use decoy traffic,
    however in the Loopix design there are three different kinds of decoy
    traffic that serve different purposes.

6. How do mix networks compare to Vuvuzela?

   Vuvuzela is a mix network design. Let's rephrase the question:
   How does Vuvuzela differ from Loopix/Katzenpost?

   Vuvuzela uses the cascade mix topology which does not scale
   well with respect to an increase in user traffic. Loopix uses
   the stratified topology which scales very well. In Vuvuzela, messages cannot
   be received when a user is offline. In Loopix messages received
   while a user is offline are queued by their Provider. Vuvuzela operates
   in rounds whereas Loopix does not.

7. How do mix networks compare to AnonPOP?

   AnonPOP is a mix network design. Let's rephrase the question:
   How does AnonPOP differ from Loopix/Katzenpost?

   AnonPOP operates in rounds and provides offline storage of messages.
   Loopix uses a continuous time mix strategy so that it avoids
   user synchronization issues.
