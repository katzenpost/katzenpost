Glossary
========

.. glossary::

    Mix
        A server that provides anonymity to clients. This is accomplished 
        by accepting layer-encrypted packets from a Provider or another
        Mix, decrypting a layer of the encryption, delaying the packet,
        and transmitting the packet to another Mix or Provider.

    Mixnet
        A network of :term:`mix`\ es. Fundamentally a mix network is a
        lossy packet switching network on which we can build reliable
        protocols. We therefore utilize a variety of designs from both
        the mix network and classical internet protocol literature to
        design an end to end reliability protocol that utilizes a mix
        network.

    Provider
        A service operated by a third party that :term:`Client`s communicate
        directly with to communicate with the Mixnet. It is responsible
        for :term:`Client` authentication, forwarding outgoing messages to the
        Mixnet, and storing incoming messages for the :term:`Client`. The
        :term:`Provider` MUST have the ability to perform cryptographic
        operations on the relayed packets.

    Node
        A :term:`Mix` or :term:`Provider` instance.

    User
        An agent using the term:`Katzenpost` system.

    Client
        Software run by the :term:`User` on its local device to participate
        in the :term:`Mixnet`.

    Panoramix
        A project funded by the European Union's Horizon 2020 research and
        innovation programme to research :term:`mixnet`\s for voting, statistics,
        and messaging, running from 2015 to 2019. See `panoramix-project.eu <https://panoramix-project.eu/>`_.
    
    Katzenpost
        A mixnet design and reference implementation based on the :term:`Loopix`
        research with added message transport reliability using :term:`ARQ`\s.

    Loopix
        The Loopix mixnet design is described in the paper `"The Loopix Anonymity
        System" published at USENIX 2017 <https://arxiv.org/pdf/1703.00536.pdf>`_.
        Loopix uses a collection of proven mix network designs to create a
        messaging system that has the property of  sender and receiver anonymity
        with respect to third party observers. Loopix uses the :term:`Sphinx`
        cryptographic packet format, various kinds of :term:`decoy traffic` and
        a :term:`stratified mix topology`.


