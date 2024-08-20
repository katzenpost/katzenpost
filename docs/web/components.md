---
generator: DocBook XSL Stylesheets V1.79.2
title: Chapter 1. Components of the Katzenpost mixnet
---

::: chapter
::: titlepage
<div>

<div>

## []{#components}Chapter 1. Components of the Katzenpost mixnet {#chapter-1.-components-of-the-katzenpost-mixnet .title}

</div>

</div>
:::

::: toc
**Table of Contents**

```{=html}
<dl class="toc">
```
```{=html}
<dt>
```
[[Directory authorities](#auth)]{.section}
```{=html}
</dt>
```
```{=html}
<dd>
```
```{=html}
<dl>
```
```{=html}
<dt>
```
[[Configuring directory authorities](#auth-config)]{.section}
```{=html}
</dt>
```
```{=html}
</dl>
```
```{=html}
</dd>
```
```{=html}
<dt>
```
[[Mix, gateway, and service nodes](#server)]{.section}
```{=html}
</dt>
```
```{=html}
<dd>
```
```{=html}
<dl>
```
```{=html}
<dt>
```
[[Configuring mix nodes](#mix-config)]{.section}
```{=html}
</dt>
```
```{=html}
<dt>
```
[[Configuring gateway nodes](#gateway-config)]{.section}
```{=html}
</dt>
```
```{=html}
<dt>
```
[[Configuring service nodes](#service-config)]{.section}
```{=html}
</dt>
```
```{=html}
</dl>
```
```{=html}
</dd>
```
```{=html}
</dl>
```
:::

`<!--
         AWS model for APIs:
         Definition] 
         Type: String
         Length Constraints: Maximum length of 256.
         Pattern: ^[A-Za-z0-9+/=]+$
         Required: No  -->`{=html}

To do: Introduction

::: section
::: titlepage
<div>

<div>

## []{#auth}Directory authorities {#directory-authorities .title style="clear: both"}

</div>

</div>
:::

To do: Introduction

::: section
::: titlepage
<div>

<div>

### []{#auth-config}Configuring `<!--directory
                authorities-->`{=html} `<!--author="dwrob" timestamp="20240820T081823+0200" comment="After first use, should we refer to directory authorites as authorities, nodes, or peers?"-->`{=html}directory authorities {#configuring-directory-authorities .title}

</div>

</div>
:::

The following configuration draws from the reference implementation in
`katzenpost/docker/voting_mixnet/auth1/authority.toml`{.filename}. In a
real-world mixnet, the component peers would not be sharing a single IP
address. For more information about the test mixnet, see [Using the
Katzenpost test network](#){.link}.

::: {.note style="margin-left: 0.5in; margin-right: 0.5in;"}
  --------------------------------------------------------------------------------------------- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
   ![\[Note\]](file:/usr/local/Oxygen%20XML%20Editor%2026/frameworks/docbook/css/img/note.png)  Note
                                                                                                Katzenpost configuration files are written in [TOML](https://toml.io/en/v1.0.0){.link target="_top"}. A block within single square brackets describes a [*table*]{.emphasis}, which is a list of key/value pairs. A block within double square brackets describes an array of tables, where the declaration is also the first element of the array.
  --------------------------------------------------------------------------------------------- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
:::

::: section
::: titlepage
<div>

<div>

#### []{#auth-server-section-config}Server section {#server-section .title}

</div>

</div>
:::

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/authority/voting/server/config/config.go#L415-->`{=html}

To do: Introduction

``` programlisting
[Server]     Identifier = "auth1"     WireKEMScheme = "xwing"     PKISignatureScheme = "Ed25519"     Addresses = ["127.0.0.1:30001"]     DataDir = "/voting_mixnet/auth1"
```

::: itemizedlist
-   [**Identifier**]{.bold}

    A human-readable identifier for the peer, for example, an FQDN.

    Type: string

-   [**WireKEMScheme**]{.bold}

    Specifies the wire protocol KEM scheme to use.

    Type: string

-   [**PKISignatureScheme**]{.bold}

    Specifies the cryptographic signature scheme.

    Type: string

-   [**Addresses**]{.bold}

    A list of IP address/port combinations that the peer will bind to
    for incoming connections.

    Type: \[\]string

-   [**DataDir**]{.bold}

    The absolute path to the peer\'s state files.

    Type: string
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#auth-authorities-section-config}Authorities section {#authorities-section .title}

</div>

</div>
:::

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/authority/voting/server/config/config.go#L266-->`{=html}

An Authorities section is configured for each peer directory authority.

``` programlisting
[[Authorities]]     Identifier = "auth1"     IdentityPublicKey = "-----BEGIN ED25519 PUBLIC KEY-----\n/v3qYgh2TvV5ZqEVgwcjJHG026KlRV6HC16xZS3TkiI=\n-----END ED25519 PUBLIC KEY-----\n"     PKISignatureScheme = "Ed25519"     LinkPublicKey = "-----BEGIN XWING PUBLIC KEY-----\nJeFaZoYQEOO71zPFFWjL7DyDp4gckGiiqLCB2RNwMacZ7wuroYugiXyir+eqvkpe\nw5k3sqm9LlS5xaEqsmJpRxYCOmaHdXARwNA6rOFwEANrZFO>     WireKEMScheme = "xwing"     Addresses = ["127.0.0.1:30001"]  [[Authorities]]     Identifier = "auth2"     IdentityPublicKey = "-----BEGIN ED25519 PUBLIC KEY-----\n60KQRhG7njt+kLQuwWlfRzJeOp4elM1/k26U/k52SjI=\n-----END ED25519 PUBLIC KEY-----\n"     PKISignatureScheme = "Ed25519"     LinkPublicKey = "-----BEGIN XWING PUBLIC KEY-----\nHVR2m7i6G6cf1qxUvyEr3KC7JvAMv5Or1rgzvUcllnmhN8BGmOmWhrWLggBNsyyS\nx+gbkfczC8WZr4GDAXOmGchhEYRy9opjqxEBENW9IHU1Dvh>     WireKEMScheme = "xwing"     Addresses = ["127.0.0.1:30002"]  [[Authorities]]     Identifier = "auth3"     IdentityPublicKey = "-----BEGIN ED25519 PUBLIC KEY-----\naZUXqznyLO2mKDceIDs0obU6GAFZa3eKUDXo2RyWpBk=\n-----END ED25519 PUBLIC KEY-----\n"     PKISignatureScheme = "Ed25519"     LinkPublicKey = "-----BEGIN XWING PUBLIC KEY-----\nEZukXtZwHTjGj7tCI0kmUcq0QEtA4HMIz2OPiXQVeaK9XVBDNQUKq8iGRvzJAodM\nmJiEXYw6vvTJhPaik4OgMpZvwQYNn9BmwrcE7VxQfuaD2Zc>     WireKEMScheme = "xwing"     Addresses = ["127.0.0.1:30003"]
```

::: itemizedlist
-   [**Identifier**]{.bold}

    A human-readable identifier for the peer, for example, an FQDN.

    Type: string

-   [**IdentityPublicKey**]{.bold}

    The peer\'s public identity key in PEM format.

    Type: sign.PublicKey

-   [**PKISignatureScheme**]{.bold}

    Specifies the peer\'s cryptographic signature scheme.

    Type: string

-   [**LinkPublicKey**]{.bold}

    The peer\'s public link layer key in PEM format.

    Type: kem.PublicKey

-   [**WireKEMScheme**]{.bold}

    Specifies the wire protocol KEM scheme to use.

    Type: string

-   [**Addresses**]{.bold}

    A list of local IP address/port combinations that the peer will bind
    to for incoming connections. These can be specified as either IPv4
    or IPv6 addresses.

    Type: \[\]string
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#auth-logging}Logging section {#logging-section .title}

</div>

</div>
:::

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/authority/voting/server/config/config.go#L78-->`{=html}

The logging configuration section controls log storage and logging
level.

``` programlisting
[Logging]     Disable = false     File = "katzenpost.log"     Level = "INFO"
```

::: itemizedlist
-   [**Disable**]{.bold}

    If [**true**]{.bold}, logging is disabled.

    Type: bool

-   [**File**]{.bold}

    Specifies the log file. If omitted, logging is written to stdout.

    Type: string

-   [**Level**]{.bold}

    Supported values are ERROR \| WARNING \| NOTICE \|INFO \| DEBUG.

    Type: string

    ::: {.warning style="margin-left: 0.5in; margin-right: 0.5in;"}
      --------------------------------------------------------------------------------------------------- ----------------------------------------------------------------------------------------------
       ![\[Warning\]](file:/usr/local/Oxygen%20XML%20Editor%2026/frameworks/docbook/css/img/warning.png)  Warning
                                                                                                          The DEBUG log level is unsafe for production use because it discloses sensitive information.
      --------------------------------------------------------------------------------------------------- ----------------------------------------------------------------------------------------------
    :::
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#auth-parameters}Parameters section {#parameters-section .title}

</div>

</div>
:::

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/authority/voting/server/config/config.go#L103
                  -->`{=html}

`<!--The
                    Parameters section defines the values of network parameters.-->`{=html}
`<!--author="dwrob" timestamp="20240820T084006+0200" comment="I am only pretending to understand the math involved here, so please read my wording critically."-->`{=html}The
Parameters section defines the values of network parameters.

``` programlisting
[Parameters]     SendRatePerMinute = 0     Mu = 0.005     MuMaxDelay = 1000     LambdaP = 0.001     LambdaPMaxDelay = 1000     LambdaL = 0.0005     LambdaLMaxDelay = 1000     LambdaD = 0.0005     LambdaDMaxDelay = 3000     LambdaM = 0.0005     LambdaG = 0.0     LambdaMMaxDelay = 100     LambdaGMaxDelay = 100
```

::: itemizedlist
-   [**SendRatePerMinute**]{.bold}

    `<!--Maximum
                                rate of packets per client per minute.-->`{=html}
    `<!--author="dwrob" timestamp="20240820T083150+0200" comment="Why is this set to zero?"-->`{=html}Maximum
    rate of packets per client per minute.

    Type: uint64

-   [**Mu**]{.bold}

    The `<!--inverse
                                of the mean of the exponential distribution-->`{=html}
    `<!--author="dwrob" timestamp="20240820T125059+0200" comment="Could we just substitute &quot;rate parameter&quot; for each use of this phrase?"-->`{=html}inverse
    of the mean of the exponential distribution used to determine the
    Sphinx packet per-hop mixing delay.

    Type: float64

-   [**MuMaxDelay**]{.bold}

    Sets the maximum delay for Mu, in millisecods.

    Type: uint64

-   [**LambdaP**]{.bold}

    Specifies the inverse of the mean of the exponential distribution
    that a client uses to determine the delay interval between packets
    leaving its FIFO egress queue or, if the queue is empty, before
    dropping decoy packets.

    Type: float64

-   [**LambdaPMaxDelay**]{.bold}

    Sets the maximum delay for LambdaP, in milliseconds.

    Type: uint64

-   [**LambdaL**]{.bold}

    Specifies the inverse of the mean of the exponential distribution
    that clients use to select the delay interval between loop decoy
    packets.

    Type: float64

-   [**LambdaLMaxDelay**]{.bold}

    Sets the maximum delay for LambdaL, in milliseconds.

    Type: uint64

-   [**LambdaD**]{.bold}

    Specifies the inverse of the mean of the exponential distribution
    that clients use to determine the delay interval before sending
    decoy drop messages.

    Type: float64

-   [**LambdaDMaxDelay**]{.bold}

    Sets the maximum delay for LambdaD, in milliseconds.

    Type: uint64

-   [**LambdaM**]{.bold}

    Specifies the inverse of the mean of the exponential distribution
    that mixes use to determine the send timing of mix loop decoy
    traffic.

    Type: float64

-   [**LambdaG**]{.bold}

    Specifies the inverse of the mean of the exponential distribution
    that is used to select the delay between sending gateway node
    decoys.

    ::: {.warning style="margin-left: 0.5in; margin-right: 0.5in;"}
    +:---------------------------------:+:----------------------------------+
    | ![\[Warning\]](file:/usr/local/   | Warning                           |
    | Oxygen%20XML%20Editor%2026/framew |                                   |
    | orks/docbook/css/img/warning.png) |                                   |
    +-----------------------------------+-----------------------------------+
    |                                   | `<!---->`{=html}                  |
    |                                   | `<!--author="dwrob"               |
    |                                   |  timestamp="20240820T125859+0200" |
    |                                   |  comment="What does this mean and |
    |                                   |  why is it a warning?"-->`{=html} |
    |                                   | This is not used via the TOML     |
    |                                   | config file; this field is only   |
    |                                   | used internally by the dirauth    |
    |                                   | server state machine.             |
    +-----------------------------------+-----------------------------------+
    :::

    Type: float64

-   [**LambdaMMaxDelay**]{.bold}

    Sets the maximum delay for LambdaM, in milliseconds.

    Type: uint64

-   [**LambdaGMaxDelay**]{.bold}

    Sets the maximum delay for LambdaG, in milliseconds.

    Type: uint64
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#auth-debug}Debug section {#debug-section .title}

</div>

</div>
:::

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/authority/voting/server/config/config.go#L235-->`{=html}

To do: Introduction

``` programlisting
[Debug]     Layers = 3     MinNodesPerLayer = 1     GenerateOnly = false
```

::: itemizedlist
-   [**Layers**]{.bold}

    Number of `<!--non-provider
                                layers-->`{=html}
    `<!--author="dwrob" timestamp="20240820T130248+0200" comment="What are these, is is &quot;provider&quot; the desired term here?"-->`{=html}non-provider
    layers in the network topology.

    Type: int

-   [**MinNodesrPerLayer**]{.bold}

    Minimum number of `<!--nodes-->`{=html}
    `<!--author="dwrob" timestamp="20240820T130325+0200" comment="What kind of nodes are these?"-->`{=html}nodes
    per layer required to form a valid consensus document.

    Type: int

-   [**GenerateOnly**]{.bold}

    If set to true, the server halts and cleans up the data directory
    immediately after long-term key generation.

    Type: bool
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#auth-mixes-section-config}Mixes sections {#mixes-sections .title}

</div>

</div>
:::

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/authority/voting/server/config/config.go#L383-->`{=html}

`<!--The
                    Mixes configuration section lists mix nodes that are known to the
                    authority.-->`{=html}
`<!--author="dwrob" timestamp="20240814T111809-0700" comment="These definitions differ significantly from the code comments."-->`{=html}The
Mixes configuration section lists mix nodes that are known to the
authority.

``` programlisting
[[Mixes]]     Identifier = "mix1"     IdentityPublicKeyPem = "../mix1/identity.public.pem"  [[Mixes]]     Identifier = "mix2"     IdentityPublicKeyPem = "../mix2/identity.public.pem"  [[Mixes]]     Identifier = "mix3"     IdentityPublicKeyPem = "../mix3/identity.public.pem"
```

::: itemizedlist
-   [**Identifier**]{.bold}

    A human readable mix node identifier.

    Type: string

-   [**IdentityPublicKeyPem**]{.bold}

    Path and file name of a mix node\'s public EdDSA signing key, also
    known as the identity key, in Base16 or Base64 format.

    Type: string
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#auth-gatewaynodes-section-config}GatewayNodes sections {#gatewaynodes-sections .title}

</div>

</div>
:::

`<!---->`{=html}
`<!--author="dwrob" timestamp="20240814T111809-0700" comment="These definitions differ significantly from the code comments."-->`{=html}

The GatewayNodes configuration section lists gateway nodes that are
known to the authority.

``` programlisting
[[GatewayNodes]]     Identifier = "gateway1"     IdentityPublicKeyPem = "../gateway1/identity.public.pem"
```

::: itemizedlist
-   [**Identifier**]{.bold}

    A human readable gateway node identifier.

    Type: string

-   [**IdentityPublicKeyPem**]{.bold}

    Path and file name of a gateway node\'s public EdDSA signing key,
    also known as the identity key, in Base16 or Base64 format.

    Type: string
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#auth-servicenodes-section-config}ServiceNodes sections {#servicenodes-sections .title}

</div>

</div>
:::

`<!---->`{=html}
`<!--author="dwrob" timestamp="20240814T111809-0700" comment="These definitions differ significantly from the code comments."-->`{=html}

The ServiceNodes configuration section lists service nodes that are
known to the authority.

``` programlisting
[[ServiceNodes]]     Identifier = "servicenode1"     IdentityPublicKeyPem = "../servicenode1/identity.public.pem"
```

::: itemizedlist
-   [**Identifier**]{.bold}

    A human readable service node identifier.

    Type: string

-   [**IdentityPublicKeyPem**]{.bold}

    Path and file name of a service node\'s public EdDSA signing key,
    also known as the identity key, in Base16 or Base64 format.

    Type: string
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#auth-topology}Topology section {#topology-section .title}

</div>

</div>
:::

The Topology configuration section defines the layers of the mix network
and the mix nodes in each layer.

``` programlisting
[Topology]                          [[Topology.Layers]]              [[Topology.Layers.Nodes]]             Identifier = "mix1"             IdentityPublicKeyPem = "../mix1/identity.public.pem"          [[Topology.Layers]]              [[Topology.Layers.Nodes]]             Identifier = "mix2"             IdentityPublicKeyPem = "../mix2/identity.public.pem"          [[Topology.Layers]]              [[Topology.Layers.Nodes]]             Identifier = "mix3"             IdentityPublicKeyPem = "../mix3/identity.public.pem"
```

::: itemizedlist
-   [**Identifier**]{.bold}

    A human readable mix node identifier.

    Type: string

-   [**IdentityPublicKeyPem**]{.bold}

    Path and file name of a mix node\'s public EdDSA signing key, also
    known as the identity key, in Base16 or Base64 format.

    Type: string
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#auth-sphinx-config}SphinxGeometry section {#sphinxgeometry-section .title}

</div>

</div>
:::

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/core/sphinx/geo/geo.go#L40-->`{=html}

To do: Introduction

``` programlisting
[SphinxGeometry]     PacketLength = 3082     NrHops = 5     HeaderLength = 476     RoutingInfoLength = 410     PerHopRoutingInfoLength = 82     SURBLength = 572     SphinxPlaintextHeaderLength = 2     PayloadTagLength = 32     ForwardPayloadLength = 2574     UserForwardPayloadLength = 2000     NextNodeHopLength = 65     SPRPKeyMaterialLength = 64     NIKEName = "x25519"     KEMName = ""
```

::: itemizedlist
-   [**PacketLength**]{.bold}

    PacketLength is the total length of a Sphinx packet.

    Type: int

-   [**NrHops**]{.bold}

    NrHops is the number of permitted hops for a packet. This setting
    influences the size of the Sphinx packet header.

    Type: int

-   [**HeaderLength**]{.bold}

    HeaderLength is the length of the Sphinx packet header in bytes.

    Type: int

-   [**RoutingInfoLength**]{.bold}

    RoutingInfoLength is the length of the routing info portion of the
    Sphinx packet header.

    Type: int

-   [**PerHopRoutingInfoLength**]{.bold}

    PerHopRoutingInfoLength is the length of the per-hop routing info in
    the Sphinx packet header.

    Type: int

-   [**SURBLength**]{.bold}

    SURBLength is the length of SURB.

    Type: int

-   [**SphinxPlaintextHeaderLength**]{.bold}

    SphinxPlaintextHeaderLength is the length of the plaintext header.

    Type: int

-   [**PayloadTagLength**]{.bold}

    PayloadTagLength is the length of the payload tag.

    Type: int

-   [**ForwardPayloadLength**]{.bold}

    ForwardPayloadLength is the size of the payload.

    Type: int

-   [**UserForwardPayloadLength**]{.bold}

    The size of the Sphinx packet\'s usable payload.

    Type: int

-   [**NextNodeHopLength**]{.bold}

    NextNodeHopLength is derived from the largest routing info block
    that we expect to encounter. Everything else just has a
    NextNodeHop + NodeDelay, or a Recipient, both cases which are
    shorter.

    Type: int

-   [**SPRPKeyMaterialLength**]{.bold}

    SPRPKeyMaterialLength is the length of the SPRP key.

    Type: int

-   [**NIKEName**]{.bold}

    NIKEName is the name of the NIKE scheme used by the mixnet\'s Sphinx
    packet. NIKEName and KEMName are mutually exclusive.

    Type: string

-   [**KEMName**]{.bold}

    KEMName is the name of the KEM scheme used by the mixnet\'s Sphinx
    packets. NIKEName and KEMName are mutually exclusive.

    Type: string
:::
:::
:::
:::

::: section
::: titlepage
<div>

<div>

## []{#server}Mix, gateway, and service nodes {#mix-gateway-and-service-nodes .title style="clear: both"}

</div>

</div>
:::

`<!--
            
            https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/server/config/config.go   -->`{=html}

::: section
::: titlepage
<div>

<div>

### []{#mix-config}Configuring mix nodes {#configuring-mix-nodes .title}

</div>

</div>
:::

The following configuration is drawn from the reference implementation
in `katzenpost/docker/voting_mixnet/mix1/katzenpost.toml`{.filename}. In
a real-world mixnet, the component hosts would not be sharing a single
IP address. For more information about the test mixnet, see [Using the
Katzenpost test network](#){.link}.

::: {.note style="margin-left: 0.5in; margin-right: 0.5in;"}
  --------------------------------------------------------------------------------------------- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
   ![\[Note\]](file:/usr/local/Oxygen%20XML%20Editor%2026/frameworks/docbook/css/img/note.png)  Note
                                                                                                Katzenpost configuration files are written in [TOML](https://toml.io/en/v1.0.0){.link target="_top"}. A block within single square brackets describes a [*table*]{.emphasis}, which is a list of key/value pairs. A block within double square brackets describes an array of tables, where the declaration is also the first element of the array.
  --------------------------------------------------------------------------------------------- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
:::

::: section
::: titlepage
<div>

<div>

#### []{#mix-server-section-config}Server section {#server-section-1 .title}

</div>

</div>
:::

``` programlisting
[Server]   Identifier = "mix1"   WireKEM = "xwing"   PKISignatureScheme = "Ed25519"   Addresses = ["127.0.0.1:30008"]   OnlyAdvertiseAltAddresses = false   MetricsAddress = "127.0.0.1:30009"   DataDir = "/voting_mixnet/mix1"   IsGatewayNode = false   IsServiceNode = false   [Server.AltAddresses]
```

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/server/config/config.go#L84-->`{=html}
`<!--
                  The config code varies by role so it is not included in this entity.-->`{=html}

::: itemizedlist
-   [**Identifier**]{.bold}

    A human-readable identifier for the node, for example, an FQDN.

    Type: string

-   [**WireKEM**]{.bold}

    WireKEM is the KEM string representing the chosen KEM scheme with
    which to communicate with the mixnet and dirauth nodes.

    Type: string

-   [**PKISignatureScheme**]{.bold}

    PKISignatureScheme specifies the cryptographic signature scheme

    Type: string

-   [**Addresses**]{.bold}

    A list of IP address/port combinations that the server will bind to
    for incoming connections to the mixnet.

    Type: \[\]string

-   [**OnlyAdvertiseAltAddresses**]{.bold}

    If [**true**]{.bold}, [**true**]{.bold}, only advertise AltAddresses
    to the PKI, not Addresses.

    Type: bool

-   [**MetricsAddress**]{.bold}

    MetricsAddress is the IP address/port to bind the prometheus metrics
    endpoint to.

    Type: string

-   [**DataDir**]{.bold}

    DataDir is the absolute path to the server\'s state files.

    Type: string

-   [**IsGatewayNode**]{.bold}

    If [**true**]{.bold}, specifies that the server is a gateway node.

    Type: bool

-   [**IsServiceNode**]{.bold}

    If [**true**]{.bold}, specifies that the server is a service node.

    Type: bool

-   [**\[Server.AltAddresses\]**]{.bold}

    A map of additional transport protocols and addresses at which the
    node is reachable by clients, in the form

    ``` programlisting
    [Server.AltAddresses]     TCP = ["localhost:30004"]
    ```

    Type: \[\]string
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#mix-logging-config}Logging section {#logging-section-1 .title}

</div>

</div>
:::

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/authority/voting/server/config/config.go#L78-->`{=html}

The logging configuration section controls log storage and logging
level.

``` programlisting
[Logging]     Disable = false     File = "katzenpost.log"     Level = "INFO"
```

::: itemizedlist
-   [**Disable**]{.bold}

    If [**true**]{.bold}, logging is disabled.

    Type: bool

-   [**File**]{.bold}

    Specifies the log file. If omitted, logging is written to stdout.

    Type: string

-   [**Level**]{.bold}

    Supported values are ERROR \| WARNING \| NOTICE \|INFO \| DEBUG.

    Type: string

    ::: {.warning style="margin-left: 0.5in; margin-right: 0.5in;"}
      --------------------------------------------------------------------------------------------------- ----------------------------------------------------------------------------------------------
       ![\[Warning\]](file:/usr/local/Oxygen%20XML%20Editor%2026/frameworks/docbook/css/img/warning.png)  Warning
                                                                                                          The DEBUG log level is unsafe for production use because it discloses sensitive information.
      --------------------------------------------------------------------------------------------------- ----------------------------------------------------------------------------------------------
    :::
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#mix-pki-config}PKI section {#pki-section .title}

</div>

</div>
:::

The PKI section contains the directory authority configuration for a
mix, gateway, or service node.

``` programlisting
[PKI]     [PKI.Voting]              [[PKI.Voting.Authorities]]             Identifier = "auth1"             IdentityPublicKey = "-----BEGIN ED25519 PUBLIC KEY-----\n/v3qYgh2TvV5ZqEVgwcjJHG026KlRV6HC16xZS3TkiI=\n-----END ED25519 PUBLIC KEY-----\n"             PKISignatureScheme = "Ed25519"             LinkPublicKey = "-----BEGIN XWING PUBLIC KEY-----\nJeFaZoYQEOO71zPFFWjL7DyDp4gckGiiqLCB2RNwMacZ7wuroYugiXyir+eqvkpe\nw5k3sqm9LlS5xaEqsmJpRxYCOmaHdXARwNA6rOFwEAN>             WireKEMScheme = "xwing"             Addresses = ["127.0.0.1:30001"]              [[PKI.Voting.Authorities]]             Identifier = "auth2"             IdentityPublicKey = "-----BEGIN ED25519 PUBLIC KEY-----\n60KQRhG7njt+kLQuwWlfRzJeOp4elM1/k26U/k52SjI=\n-----END ED25519 PUBLIC KEY-----\n"             PKISignatureScheme = "Ed25519"             LinkPublicKey = "-----BEGIN XWING PUBLIC KEY-----\nHVR2m7i6G6cf1qxUvyEr3KC7JvAMv5Or1rgzvUcllnmhN8BGmOmWhrWLggBNsyyS\nx+gbkfczC8WZr4GDAXOmGchhEYRy9opjqxEBENW9IHU>             WireKEMScheme = "xwing"             Addresses = ["127.0.0.1:30002"]              [[PKI.Voting.Authorities]]             Identifier = "auth3"             IdentityPublicKey = "-----BEGIN ED25519 PUBLIC KEY-----\naZUXqznyLO2mKDceIDs0obU6GAFZa3eKUDXo2RyWpBk=\n-----END ED25519 PUBLIC KEY-----\n"             PKISignatureScheme = "Ed25519"             LinkPublicKey = "-----BEGIN XWING PUBLIC KEY-----\nEZukXtZwHTjGj7tCI0kmUcq0QEtA4HMIz2OPiXQVeaK9XVBDNQUKq8iGRvzJAodM\nmJiEXYw6vvTJhPaik4OgMpZvwQYNn9BmwrcE7VxQfua>             WireKEMScheme = "xwing"             Addresses = ["127.0.0.1:30003"]
```

::: itemizedlist
-   [**Identifier**]{.bold}

    A human-readable identifier for the node, for example, an FQDN.

    Type: string

-   [**IdentityPublicKey**]{.bold}

    The public identity key in PEM format.

    Type: string

-   [**PKISignatureScheme**]{.bold}

    Specifies the cryptographic signature scheme

    Type: string

-   [**LinkPublicKey**]{.bold}

    The peer\'s public link-layer key in PEM format.

    Type: string

-   [**WireKEMScheme**]{.bold}

    Specifies the wire protocol KEM scheme.

    Type: string

-   [**Addresses**]{.bold}

    A list of IP address/port combinations that
    `<!--peer authority-->`{=html}
    `<!--author="dwrob" timestamp="20240814T170317-0700" comment="Should be &quot;the service node&quot;?"-->`{=html}peer
    authority uses for the Directory Authority service.

    Type: \[\]string
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#mix-management-config}Management section {#management-section .title}

</div>

</div>
:::

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/server/config/config.go#L729-->`{=html}

Management is the Katzenpost management interface configuration. The
management section specifies connectivity information for the Katzenpost
control protocol which can be used to make configuration changes during
run-time. An example configuration looks like this:

``` programlisting
[Management]     Enable = false     Path = "/voting_mixnet/mix1/management_sock"
```

::: itemizedlist
-   [**Enable**]{.bold}

    Enables the management interface if set to true.

    Type: bool

-   [**Path**]{.bold}

    Specifies the path to the management interface socket. `<!--If
                                left empty, then management_sock will be used under the DataDir.-->`{=html}
    `<!--author="dwrob" timestamp="20240814T171718-0700" comment="Confusing wording."-->`{=html}If
    left empty, then management_sock will be used under the DataDir.

    Type: string
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#mix-sphinx-config}SphinxGeometry section {#sphinxgeometry-section-1 .title}

</div>

</div>
:::

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/core/sphinx/geo/geo.go#L40-->`{=html}

To do: Introduction

``` programlisting
[SphinxGeometry]     PacketLength = 3082     NrHops = 5     HeaderLength = 476     RoutingInfoLength = 410     PerHopRoutingInfoLength = 82     SURBLength = 572     SphinxPlaintextHeaderLength = 2     PayloadTagLength = 32     ForwardPayloadLength = 2574     UserForwardPayloadLength = 2000     NextNodeHopLength = 65     SPRPKeyMaterialLength = 64     NIKEName = "x25519"     KEMName = ""
```

::: itemizedlist
-   [**PacketLength**]{.bold}

    PacketLength is the total length of a Sphinx packet.

    Type: int

-   [**NrHops**]{.bold}

    NrHops is the number of permitted hops for a packet. This setting
    influences the size of the Sphinx packet header.

    Type: int

-   [**HeaderLength**]{.bold}

    HeaderLength is the length of the Sphinx packet header in bytes.

    Type: int

-   [**RoutingInfoLength**]{.bold}

    RoutingInfoLength is the length of the routing info portion of the
    Sphinx packet header.

    Type: int

-   [**PerHopRoutingInfoLength**]{.bold}

    PerHopRoutingInfoLength is the length of the per-hop routing info in
    the Sphinx packet header.

    Type: int

-   [**SURBLength**]{.bold}

    SURBLength is the length of SURB.

    Type: int

-   [**SphinxPlaintextHeaderLength**]{.bold}

    SphinxPlaintextHeaderLength is the length of the plaintext header.

    Type: int

-   [**PayloadTagLength**]{.bold}

    PayloadTagLength is the length of the payload tag.

    Type: int

-   [**ForwardPayloadLength**]{.bold}

    ForwardPayloadLength is the size of the payload.

    Type: int

-   [**UserForwardPayloadLength**]{.bold}

    The size of the Sphinx packet\'s usable payload.

    Type: int

-   [**NextNodeHopLength**]{.bold}

    NextNodeHopLength is derived from the largest routing info block
    that we expect to encounter. Everything else just has a
    NextNodeHop + NodeDelay, or a Recipient, both cases which are
    shorter.

    Type: int

-   [**SPRPKeyMaterialLength**]{.bold}

    SPRPKeyMaterialLength is the length of the SPRP key.

    Type: int

-   [**NIKEName**]{.bold}

    NIKEName is the name of the NIKE scheme used by the mixnet\'s Sphinx
    packet. NIKEName and KEMName are mutually exclusive.

    Type: string

-   [**KEMName**]{.bold}

    KEMName is the name of the KEM scheme used by the mixnet\'s Sphinx
    packets. NIKEName and KEMName are mutually exclusive.

    Type: string
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#mix-debug-config}Debug section {#debug-section-1 .title}

</div>

</div>
:::

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/server/config/config.go-->`{=html}

The Katzenpost server debug configuration is used for advanced tuning.

``` programlisting
[Debug]                     NumSphinxWorkers = 16                     NumServiceWorkers = 3                     NumGatewayWorkers = 3                     NumKaetzchenWorkers = 3                     SchedulerExternalMemoryQueue = false                     SchedulerQueueSize = 0                     SchedulerMaxBurst = 16                     UnwrapDelay = 250                     GatewayDelay = 500                     ServiceDelay = 500                     KaetzchenDelay = 750                     SchedulerSlack = 150                     SendSlack = 50                     DecoySlack = 15000                     ConnectTimeout = 60000                     HandshakeTimeout = 30000                     ReauthInterval = 30000                     SendDecoyTraffic = false                     DisableRateLimit = false                     GenerateOnly = false
```

::: itemizedlist
`<!--
                     Worker "processes"?-->`{=html}

-   [**NumSphinxWorkers**]{.bold}

    Specifies the number of worker instances for processing inbound
    Sphinx packets.

    Type: int

-   [**NumProviderWorkers**]{.bold}

    Specifies the number of worker instances for processing
    provider-specific packets.

    Type: int

-   [**NumKaetzchenWorkers**]{.bold}

    Specifies the number of worker instances for processing
    Kaetzchen-specific packets.

    Type: int

-   [**SchedulerExternalMemoryQueue**]{.bold}

    If [**true**]{.bold}, enables the experimental external memory queue
    that is backed backed up to disk.

    Type: bool

-   [**SchedulerQueueSize**]{.bold}

    The maximum allowed scheduler queue size before random entries will
    start getting dropped. A value \<= 0 is treated as unlimited.

    Type: int

-   [**SchedulerMaxBurst**]{.bold}

    The maximum number of packets that will be dispatched per scheduler
    wakeup event.

    Type:

-   [**UnwrapDelay**]{.bold}

    The maximum allowed unwrap delay due to queueing, in milliseconds.

    Type: int

-   [**GatewayDelay**]{.bold}

    The maximum allowed gateway node worker delay due to queueing, in
    milliseconds.

    Type: int

-   [**ServiceDelay**]{.bold}

    The maximum allowed provider delay due to queueing, in milliseconds.

    Type: int

-   [**KaetzchenDelay**]{.bold}

    The maximum allowed kaetzchen delay due to queueing, in
    milliseconds.

    Type: int

-   [**SchedulerSlack**]{.bold}

    The maximum allowed scheduler slack due to queueing and/or
    processing, in milliseconds.

    Type: int

-   [**SendSlack**]{.bold}

    The maximum allowed send queue slack due to queueing and/or
    congestion, in milliseconds.

    Type: int

-   [**DecoySlack**]{.bold}[]{.bold}

    The maximum allowed decoy sweep slack due to various external
    delays, such as latency, before a loop decoy packet will be
    considered lost.

    Type: int

-   [**ConnectTimeout**]{.bold}

    Specifies the maximum time a connection can take to establish a
    TCP/IP connection, in milliseconds.

    Type: int

-   [**HandshakeTimeout**]{.bold}

    Specifies the maximum time a connection can take for a link protocol
    handshake, in milliseconds.

    Type: int

-   [**ReauthInterval**]{.bold}

    Specifies the interval after which a connection will be
    reauthenticated, in milliseconds.

    Type: int

-   [**SendDecoyTraffic**]{.bold}

    If [**true**]{.bold}, enables sending decoy traffic. Disabled by
    default.

    Type: bool

-   [**DisableRateLimit**]{.bold}

    If [**true**]{.bold}, disables the per-client rate limiter. This
    option should only be used for testing.

    Type: bool

-   [**GenerateOnly**]{.bold}

    If [**true**]{.bold}, halts and cleans up the server after long term
    key generation.

    Type: bool
:::
:::
:::

::: section
::: titlepage
<div>

<div>

### []{#gateway-config}Configuring gateway nodes {#configuring-gateway-nodes .title}

</div>

</div>
:::

The following configuration is drawn from the reference implementation
in
`katzenpost/docker/voting_mixnet/gateway1/katzenpost.toml`{.filename}.
In a real-world mixnet, the component hosts would not be sharing a
single IP address. For more information about the test mixnet, see
[Using the Katzenpost test network](#){.link}.

::: section
::: titlepage
<div>

<div>

#### []{#gateway-server-section-config}Server section {#server-section-2 .title}

</div>

</div>
:::

``` programlisting
[Server]     Identifier = "gateway1"     WireKEM = "xwing"     PKISignatureScheme = "Ed25519"     Addresses = ["127.0.0.1:30004"]     OnlyAdvertiseAltAddresses = false     MetricsAddress = "127.0.0.1:30005"     DataDir = "/voting_mixnet/gateway1"     IsGatewayNode = true     IsServiceNode = false     [Server.AltAddresses]         TCP = ["localhost:30004"]
```

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/server/config/config.go#L84-->`{=html}
`<!--
                  The config code varies by role so it is not included in this entity.-->`{=html}

::: itemizedlist
-   [**Identifier**]{.bold}

    A human-readable identifier for the node, for example, an FQDN.

    Type: string

-   [**WireKEM**]{.bold}

    WireKEM is the KEM string representing the chosen KEM scheme with
    which to communicate with the mixnet and dirauth nodes.

    Type: string

-   [**PKISignatureScheme**]{.bold}

    PKISignatureScheme specifies the cryptographic signature scheme

    Type: string

-   [**Addresses**]{.bold}

    A list of IP address/port combinations that the server will bind to
    for incoming connections to the mixnet.

    Type: \[\]string

-   [**OnlyAdvertiseAltAddresses**]{.bold}

    If [**true**]{.bold}, [**true**]{.bold}, only advertise AltAddresses
    to the PKI, not Addresses.

    Type: bool

-   [**MetricsAddress**]{.bold}

    MetricsAddress is the IP address/port to bind the prometheus metrics
    endpoint to.

    Type: string

-   [**DataDir**]{.bold}

    DataDir is the absolute path to the server\'s state files.

    Type: string

-   [**IsGatewayNode**]{.bold}

    If [**true**]{.bold}, specifies that the server is a gateway node.

    Type: bool

-   [**IsServiceNode**]{.bold}

    If [**true**]{.bold}, specifies that the server is a service node.

    Type: bool

-   [**\[Server.AltAddresses\]**]{.bold}

    A map of additional transport protocols and addresses at which the
    node is reachable by clients, in the form

    ``` programlisting
    [Server.AltAddresses]     TCP = ["localhost:30004"]
    ```

    Type: \[\]string
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#gateway-logging-config}Logging section {#logging-section-2 .title}

</div>

</div>
:::

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/authority/voting/server/config/config.go#L78-->`{=html}

The logging configuration section controls log storage and logging
level.

``` programlisting
[Logging]     Disable = false     File = "katzenpost.log"     Level = "INFO"
```

::: itemizedlist
-   [**Disable**]{.bold}

    If [**true**]{.bold}, logging is disabled.

    Type: bool

-   [**File**]{.bold}

    Specifies the log file. If omitted, logging is written to stdout.

    Type: string

-   [**Level**]{.bold}

    Supported values are ERROR \| WARNING \| NOTICE \|INFO \| DEBUG.

    Type: string

    ::: {.warning style="margin-left: 0.5in; margin-right: 0.5in;"}
      --------------------------------------------------------------------------------------------------- ----------------------------------------------------------------------------------------------
       ![\[Warning\]](file:/usr/local/Oxygen%20XML%20Editor%2026/frameworks/docbook/css/img/warning.png)  Warning
                                                                                                          The DEBUG log level is unsafe for production use because it discloses sensitive information.
      --------------------------------------------------------------------------------------------------- ----------------------------------------------------------------------------------------------
    :::
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#gateway-gateway-section-config}Gateway section {#gateway-section .title}

</div>

</div>
:::

`<!---->`{=html}
`<!--author="dwrob" timestamp="20240816T143000-0700" comment="More information needed."-->`{=html}

``` programlisting
[Gateway]     [Gateway.UserDB]         Backend = "bolt"             [Gateway.UserDB.Bolt]                 UserDB = "/voting_mixnet/gateway1/users.db"     [Gateway.SpoolDB]         Backend = "bolt"             [Gateway.SpoolDB.Bolt]                 SpoolDB = "/voting_mixnet/gateway1/spool.db"
```

::: itemizedlist
-   `<!---->`{=html}
    `<!--author="dwrob" timestamp="20240820T160307+0200" comment="To do"-->`{=html}

-   

-   
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#gateway-pki-config}PKI section {#pki-section-1 .title}

</div>

</div>
:::

The PKI section contains the directory authority configuration for a
mix, gateway, or service node.

``` programlisting
[PKI]     [PKI.Voting]              [[PKI.Voting.Authorities]]             Identifier = "auth1"             IdentityPublicKey = "-----BEGIN ED25519 PUBLIC KEY-----\n/v3qYgh2TvV5ZqEVgwcjJHG026KlRV6HC16xZS3TkiI=\n-----END ED25519 PUBLIC KEY-----\n"             PKISignatureScheme = "Ed25519"             LinkPublicKey = "-----BEGIN XWING PUBLIC KEY-----\nJeFaZoYQEOO71zPFFWjL7DyDp4gckGiiqLCB2RNwMacZ7wuroYugiXyir+eqvkpe\nw5k3sqm9LlS5xaEqsmJpRxYCOmaHdXARwNA6rOFwEAN>             WireKEMScheme = "xwing"             Addresses = ["127.0.0.1:30001"]              [[PKI.Voting.Authorities]]             Identifier = "auth2"             IdentityPublicKey = "-----BEGIN ED25519 PUBLIC KEY-----\n60KQRhG7njt+kLQuwWlfRzJeOp4elM1/k26U/k52SjI=\n-----END ED25519 PUBLIC KEY-----\n"             PKISignatureScheme = "Ed25519"             LinkPublicKey = "-----BEGIN XWING PUBLIC KEY-----\nHVR2m7i6G6cf1qxUvyEr3KC7JvAMv5Or1rgzvUcllnmhN8BGmOmWhrWLggBNsyyS\nx+gbkfczC8WZr4GDAXOmGchhEYRy9opjqxEBENW9IHU>             WireKEMScheme = "xwing"             Addresses = ["127.0.0.1:30002"]              [[PKI.Voting.Authorities]]             Identifier = "auth3"             IdentityPublicKey = "-----BEGIN ED25519 PUBLIC KEY-----\naZUXqznyLO2mKDceIDs0obU6GAFZa3eKUDXo2RyWpBk=\n-----END ED25519 PUBLIC KEY-----\n"             PKISignatureScheme = "Ed25519"             LinkPublicKey = "-----BEGIN XWING PUBLIC KEY-----\nEZukXtZwHTjGj7tCI0kmUcq0QEtA4HMIz2OPiXQVeaK9XVBDNQUKq8iGRvzJAodM\nmJiEXYw6vvTJhPaik4OgMpZvwQYNn9BmwrcE7VxQfua>             WireKEMScheme = "xwing"             Addresses = ["127.0.0.1:30003"]
```

::: itemizedlist
-   [**Identifier**]{.bold}

    A human-readable identifier for the node, for example, an FQDN.

    Type: string

-   [**IdentityPublicKey**]{.bold}

    The public identity key in PEM format.

    Type: string

-   [**PKISignatureScheme**]{.bold}

    Specifies the cryptographic signature scheme

    Type: string

-   [**LinkPublicKey**]{.bold}

    The peer\'s public link-layer key in PEM format.

    Type: string

-   [**WireKEMScheme**]{.bold}

    Specifies the wire protocol KEM scheme.

    Type: string

-   [**Addresses**]{.bold}

    A list of IP address/port combinations that
    `<!--peer authority-->`{=html}
    `<!--author="dwrob" timestamp="20240814T170317-0700" comment="Should be &quot;the service node&quot;?"-->`{=html}peer
    authority uses for the Directory Authority service.

    Type: \[\]string
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#gateway-management-config}Management section {#management-section-1 .title}

</div>

</div>
:::

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/server/config/config.go#L729-->`{=html}

Management is the Katzenpost management interface configuration. The
management section specifies connectivity information for the Katzenpost
control protocol which can be used to make configuration changes during
run-time. An example configuration looks like this:

``` programlisting
[Management]     Enable = false     Path = "/voting_mixnet/mix1/management_sock"
```

::: itemizedlist
-   [**Enable**]{.bold}

    Enables the management interface if set to true.

    Type: bool

-   [**Path**]{.bold}

    Specifies the path to the management interface socket. `<!--If
                                left empty, then management_sock will be used under the DataDir.-->`{=html}
    `<!--author="dwrob" timestamp="20240814T171718-0700" comment="Confusing wording."-->`{=html}If
    left empty, then management_sock will be used under the DataDir.

    Type: string
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#gateway-sphinx-config}SphinxGeometry section {#sphinxgeometry-section-2 .title}

</div>

</div>
:::

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/core/sphinx/geo/geo.go#L40-->`{=html}

To do: Introduction

``` programlisting
[SphinxGeometry]     PacketLength = 3082     NrHops = 5     HeaderLength = 476     RoutingInfoLength = 410     PerHopRoutingInfoLength = 82     SURBLength = 572     SphinxPlaintextHeaderLength = 2     PayloadTagLength = 32     ForwardPayloadLength = 2574     UserForwardPayloadLength = 2000     NextNodeHopLength = 65     SPRPKeyMaterialLength = 64     NIKEName = "x25519"     KEMName = ""
```

::: itemizedlist
-   [**PacketLength**]{.bold}

    PacketLength is the total length of a Sphinx packet.

    Type: int

-   [**NrHops**]{.bold}

    NrHops is the number of permitted hops for a packet. This setting
    influences the size of the Sphinx packet header.

    Type: int

-   [**HeaderLength**]{.bold}

    HeaderLength is the length of the Sphinx packet header in bytes.

    Type: int

-   [**RoutingInfoLength**]{.bold}

    RoutingInfoLength is the length of the routing info portion of the
    Sphinx packet header.

    Type: int

-   [**PerHopRoutingInfoLength**]{.bold}

    PerHopRoutingInfoLength is the length of the per-hop routing info in
    the Sphinx packet header.

    Type: int

-   [**SURBLength**]{.bold}

    SURBLength is the length of SURB.

    Type: int

-   [**SphinxPlaintextHeaderLength**]{.bold}

    SphinxPlaintextHeaderLength is the length of the plaintext header.

    Type: int

-   [**PayloadTagLength**]{.bold}

    PayloadTagLength is the length of the payload tag.

    Type: int

-   [**ForwardPayloadLength**]{.bold}

    ForwardPayloadLength is the size of the payload.

    Type: int

-   [**UserForwardPayloadLength**]{.bold}

    The size of the Sphinx packet\'s usable payload.

    Type: int

-   [**NextNodeHopLength**]{.bold}

    NextNodeHopLength is derived from the largest routing info block
    that we expect to encounter. Everything else just has a
    NextNodeHop + NodeDelay, or a Recipient, both cases which are
    shorter.

    Type: int

-   [**SPRPKeyMaterialLength**]{.bold}

    SPRPKeyMaterialLength is the length of the SPRP key.

    Type: int

-   [**NIKEName**]{.bold}

    NIKEName is the name of the NIKE scheme used by the mixnet\'s Sphinx
    packet. NIKEName and KEMName are mutually exclusive.

    Type: string

-   [**KEMName**]{.bold}

    KEMName is the name of the KEM scheme used by the mixnet\'s Sphinx
    packets. NIKEName and KEMName are mutually exclusive.

    Type: string
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#gateway-debug-config}Debug section {#debug-section-2 .title}

</div>

</div>
:::

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/server/config/config.go-->`{=html}

The Katzenpost server debug configuration is used for advanced tuning.

``` programlisting
[Debug]                     NumSphinxWorkers = 16                     NumServiceWorkers = 3                     NumGatewayWorkers = 3                     NumKaetzchenWorkers = 3                     SchedulerExternalMemoryQueue = false                     SchedulerQueueSize = 0                     SchedulerMaxBurst = 16                     UnwrapDelay = 250                     GatewayDelay = 500                     ServiceDelay = 500                     KaetzchenDelay = 750                     SchedulerSlack = 150                     SendSlack = 50                     DecoySlack = 15000                     ConnectTimeout = 60000                     HandshakeTimeout = 30000                     ReauthInterval = 30000                     SendDecoyTraffic = false                     DisableRateLimit = false                     GenerateOnly = false
```

::: itemizedlist
`<!--
                     Worker "processes"?-->`{=html}

-   [**NumSphinxWorkers**]{.bold}

    Specifies the number of worker instances for processing inbound
    Sphinx packets.

    Type: int

-   [**NumProviderWorkers**]{.bold}

    Specifies the number of worker instances for processing
    provider-specific packets.

    Type: int

-   [**NumKaetzchenWorkers**]{.bold}

    Specifies the number of worker instances for processing
    Kaetzchen-specific packets.

    Type: int

-   [**SchedulerExternalMemoryQueue**]{.bold}

    If [**true**]{.bold}, enables the experimental external memory queue
    that is backed backed up to disk.

    Type: bool

-   [**SchedulerQueueSize**]{.bold}

    The maximum allowed scheduler queue size before random entries will
    start getting dropped. A value \<= 0 is treated as unlimited.

    Type: int

-   [**SchedulerMaxBurst**]{.bold}

    The maximum number of packets that will be dispatched per scheduler
    wakeup event.

    Type:

-   [**UnwrapDelay**]{.bold}

    The maximum allowed unwrap delay due to queueing, in milliseconds.

    Type: int

-   [**GatewayDelay**]{.bold}

    The maximum allowed gateway node worker delay due to queueing, in
    milliseconds.

    Type: int

-   [**ServiceDelay**]{.bold}

    The maximum allowed provider delay due to queueing, in milliseconds.

    Type: int

-   [**KaetzchenDelay**]{.bold}

    The maximum allowed kaetzchen delay due to queueing, in
    milliseconds.

    Type: int

-   [**SchedulerSlack**]{.bold}

    The maximum allowed scheduler slack due to queueing and/or
    processing, in milliseconds.

    Type: int

-   [**SendSlack**]{.bold}

    The maximum allowed send queue slack due to queueing and/or
    congestion, in milliseconds.

    Type: int

-   [**DecoySlack**]{.bold}[]{.bold}

    The maximum allowed decoy sweep slack due to various external
    delays, such as latency, before a loop decoy packet will be
    considered lost.

    Type: int

-   [**ConnectTimeout**]{.bold}

    Specifies the maximum time a connection can take to establish a
    TCP/IP connection, in milliseconds.

    Type: int

-   [**HandshakeTimeout**]{.bold}

    Specifies the maximum time a connection can take for a link protocol
    handshake, in milliseconds.

    Type: int

-   [**ReauthInterval**]{.bold}

    Specifies the interval after which a connection will be
    reauthenticated, in milliseconds.

    Type: int

-   [**SendDecoyTraffic**]{.bold}

    If [**true**]{.bold}, enables sending decoy traffic. Disabled by
    default.

    Type: bool

-   [**DisableRateLimit**]{.bold}

    If [**true**]{.bold}, disables the per-client rate limiter. This
    option should only be used for testing.

    Type: bool

-   [**GenerateOnly**]{.bold}

    If [**true**]{.bold}, halts and cleans up the server after long term
    key generation.

    Type: bool
:::
:::
:::

::: section
::: titlepage
<div>

<div>

### []{#service-config}Configuring service nodes {#configuring-service-nodes .title}

</div>

</div>
:::

The following configuration is drawn from the reference implementation
in
`katzenpost/docker/voting_mixnet/servicenode1/authority.toml`{.filename}.
In a real-world mixnet, the component hosts would not be sharing a
single IP address. For more information about the test mixnet, see
[Using the Katzenpost test network](#){.link}.

::: section
::: titlepage
<div>

<div>

#### []{#service-server-section-config}Server section {#server-section-3 .title}

</div>

</div>
:::

The Server section contains mandatory information common to all nodes,
for example:

``` programlisting
[Server]     Identifier = "servicenode1"     WireKEM = "xwing"     PKISignatureScheme = "Ed25519"     Addresses = ["127.0.0.1:30006"]     OnlyAdvertiseAltAddresses = false     MetricsAddress = "127.0.0.1:30007"     DataDir = "/voting_mixnet/servicenode1"     IsGatewayNode = false     IsServiceNode = true     [Server.AltAddresses]
```

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/server/config/config.go#L84-->`{=html}
`<!--
                  The config code varies by role so it is not included in this entity.-->`{=html}

::: itemizedlist
-   [**Identifier**]{.bold}

    A human-readable identifier for the node, for example, an FQDN.

    Type: string

-   [**WireKEM**]{.bold}

    WireKEM is the KEM string representing the chosen KEM scheme with
    which to communicate with the mixnet and dirauth nodes.

    Type: string

-   [**PKISignatureScheme**]{.bold}

    PKISignatureScheme specifies the cryptographic signature scheme

    Type: string

-   [**Addresses**]{.bold}

    A list of IP address/port combinations that the server will bind to
    for incoming connections to the mixnet.

    Type: \[\]string

-   [**OnlyAdvertiseAltAddresses**]{.bold}

    If [**true**]{.bold}, [**true**]{.bold}, only advertise AltAddresses
    to the PKI, not Addresses.

    Type: bool

-   [**MetricsAddress**]{.bold}

    MetricsAddress is the IP address/port to bind the prometheus metrics
    endpoint to.

    Type: string

-   [**DataDir**]{.bold}

    DataDir is the absolute path to the server\'s state files.

    Type: string

-   [**IsGatewayNode**]{.bold}

    If [**true**]{.bold}, specifies that the server is a gateway node.

    Type: bool

-   [**IsServiceNode**]{.bold}

    If [**true**]{.bold}, specifies that the server is a service node.

    Type: bool

-   [**\[Server.AltAddresses\]**]{.bold}

    A map of additional transport protocols and addresses at which the
    node is reachable by clients, in the form

    ``` programlisting
    [Server.AltAddresses]     TCP = ["localhost:30004"]
    ```

    Type: \[\]string
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#service-logging-config}Logging section {#logging-section-3 .title}

</div>

</div>
:::

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/authority/voting/server/config/config.go#L78-->`{=html}

The logging configuration section controls log storage and logging
level.

``` programlisting
[Logging]     Disable = false     File = "katzenpost.log"     Level = "INFO"
```

::: itemizedlist
-   [**Disable**]{.bold}

    If [**true**]{.bold}, logging is disabled.

    Type: bool

-   [**File**]{.bold}

    Specifies the log file. If omitted, logging is written to stdout.

    Type: string

-   [**Level**]{.bold}

    Supported values are ERROR \| WARNING \| NOTICE \|INFO \| DEBUG.

    Type: string

    ::: {.warning style="margin-left: 0.5in; margin-right: 0.5in;"}
      --------------------------------------------------------------------------------------------------- ----------------------------------------------------------------------------------------------
       ![\[Warning\]](file:/usr/local/Oxygen%20XML%20Editor%2026/frameworks/docbook/css/img/warning.png)  Warning
                                                                                                          The DEBUG log level is unsafe for production use because it discloses sensitive information.
      --------------------------------------------------------------------------------------------------- ----------------------------------------------------------------------------------------------
    :::
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#service-servicenode-section-config}ServiceNode section {#servicenode-section .title}

</div>

</div>
:::

`<!--
                  https://github.com/katzenpost/katzenpost/blob/main/server/config/config.go#L470 defines the top level configuration.
                  https://github.com/katzenpost/katzenpost/blob/main/genconfig/main.go#L207 defines the per-service configurations.-->`{=html}

The service node configuration section contains subsections with
settings for each service that Katzenpost supports. In a production
network, the various services would be hosted on dedicated systems.

``` programlisting
[ServiceNode]                          [[ServiceNode.Kaetzchen]]         Capability = "echo"         Endpoint = "+echo"         Disable = false          [[ServiceNode.CBORPluginKaetzchen]]         Capability = "spool"         Endpoint = "+spool"         Command = "/voting_mixnet/memspool.alpine"         MaxConcurrency = 1         Disable = false         [ServiceNode.CBORPluginKaetzchen.Config]             data_store = "/voting_mixnet/servicenode1/memspool.storage"             log_dir = "/voting_mixnet/servicenode1"          [[ServiceNode.CBORPluginKaetzchen]]         Capability = "pigeonhole"         Endpoint = "+pigeonhole"         Command = "/voting_mixnet/pigeonhole.alpine"         MaxConcurrency = 1         Disable = false         [ServiceNode.CBORPluginKaetzchen.Config]             db = "/voting_mixnet/servicenode1/map.storage"             log_dir = "/voting_mixnet/servicenode1"          [[ServiceNode.CBORPluginKaetzchen]]         Capability = "panda"         Endpoint = "+panda"         Command = "/voting_mixnet/panda_server.alpine"         MaxConcurrency = 1         Disable = false         [ServiceNode.CBORPluginKaetzchen.Config]             fileStore = "/voting_mixnet/servicenode1/panda.storage"             log_dir = "/voting_mixnet/servicenode1"             log_level = "INFO"          [[ServiceNode.CBORPluginKaetzchen]]         Capability = "http"         Endpoint = "+http"         Command = "/voting_mixnet/proxy_server.alpine"         MaxConcurrency = 1         Disable = false         [ServiceNode.CBORPluginKaetzchen.Config]             host = "localhost:4242"             log_dir = "/voting_mixnet/servicenode1"             log_level = "DEBUG"
```

[**Common parameters:**]{.bold}

::: itemizedlist
-   [**Capability**]{.bold}

    The capability exposed by the agent.

    Type: string

-   [**Endpoint**]{.bold}

    The provider-side endpoint for the agent accepts requests.
    `<!--While
                                not required by the spec, this server only-->`{=html}
    `<!--author="dwrob" timestamp="20240820T155836+0200" comment="What does this mean? Does it need to be here?"-->`{=html}While
    not required by the spec, this server only

    supports Endpoints that are lower-case local-parts of an e-mail
    address.

    Type: string

-   [**Command**]{.bold}

    The path and filename of the external plugin program that implements
    this Kaetzchen service.

    Type: string

-   [**MaxConcurrency**]{.bold}

    The number of worker goroutines to start for this service.

    Type: int

-   [**Config**]{.bold}

    The extra per-agent arguments to be passed to the agent\'s
    initialization routine.

    Type: map\[string\]interface{}

-   [**Disable**]{.bold}

    If true, disables a configured agent.

    Type: bool
:::

`<!---->`{=html}
`<!--author="dwrob" timestamp="20240816T141621-0700" comment="About CBOR:

https://pkg.go.dev/github.com/katzenpost/katzenpost@v0.0.35/server/cborplugin#ResponseFactory

Package cborplugin is a plugin system allowing mix network services to be added in any language. It communicates queries and responses to and from the mix server using CBOR over UNIX domain socket. Beyond that, a client supplied SURB is used to route the response back to the client as described in our Kaetzchen specification document: "-->`{=html}

`<!---->`{=html}
`<!--author="dwrob" timestamp="20240820T160215+0200" comment="To oo" mid="38"-->`{=html}[**Per-service
parameters:**]{.bold}

::: itemizedlist
-   `<!---->`{=html}
    `<!--author="dwrob" timestamp="20240816T124622-0700" comment="Needs explanation"-->`{=html}[**Kaetzchen**]{.bold}

-   [**spool**]{.bold}

    ::: itemizedlist
    -   [**data_store**]{.bold}

        Type:

    -   [**log_dir**]{.bold}

        Type:
    :::

-   [**pigeonhole**]{.bold}

    ::: itemizedlist
    -   [**db**]{.bold}

        Type:

    -   [**log_dir**]{.bold}

        Type:
    :::

-   [**panda**]{.bold}

    ::: itemizedlist
    -   [**fileStore**]{.bold}

        Type:

    -   [**log_dir**]{.bold}

        Type:

    -   [**log_level**]{.bold}

        Supported values are ERROR \| WARNING \| NOTICE \|INFO \| DEBUG.

        Type: string

        ::: {.warning style="margin-left: 0.5in; margin-right: 0.5in;"}
          --------------------------------------------------------------------------------------------------- ---------------------------------------------------
           ![\[Warning\]](file:/usr/local/Oxygen%20XML%20Editor%2026/frameworks/docbook/css/img/warning.png)  Warning
                                                                                                              The DEBUG log level is unsafe for production use.
          --------------------------------------------------------------------------------------------------- ---------------------------------------------------
        :::

        Type: string
    :::

-   [**http**]{.bold}

    ::: itemizedlist
    -   [**host**]{.bold}

        Type:

    -   [**log_dir**]{.bold}

        Type:

    -   [**log_level**]{.bold}

        Supported values are ERROR \| WARNING \| NOTICE \|INFO \| DEBUG.

        Type: string

        ::: {.warning style="margin-left: 0.5in; margin-right: 0.5in;"}
          --------------------------------------------------------------------------------------------------- ---------------------------------------------------
           ![\[Warning\]](file:/usr/local/Oxygen%20XML%20Editor%2026/frameworks/docbook/css/img/warning.png)  Warning
                                                                                                              The DEBUG log level is unsafe for production use.
          --------------------------------------------------------------------------------------------------- ---------------------------------------------------
        :::

        Type: string
    :::
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#service-pki-config}PKI section {#pki-section-2 .title}

</div>

</div>
:::

The PKI section contains the directory authority configuration for a
mix, gateway, or service node.

``` programlisting
[PKI]     [PKI.Voting]              [[PKI.Voting.Authorities]]             Identifier = "auth1"             IdentityPublicKey = "-----BEGIN ED25519 PUBLIC KEY-----\n/v3qYgh2TvV5ZqEVgwcjJHG026KlRV6HC16xZS3TkiI=\n-----END ED25519 PUBLIC KEY-----\n"             PKISignatureScheme = "Ed25519"             LinkPublicKey = "-----BEGIN XWING PUBLIC KEY-----\nJeFaZoYQEOO71zPFFWjL7DyDp4gckGiiqLCB2RNwMacZ7wuroYugiXyir+eqvkpe\nw5k3sqm9LlS5xaEqsmJpRxYCOmaHdXARwNA6rOFwEAN>             WireKEMScheme = "xwing"             Addresses = ["127.0.0.1:30001"]              [[PKI.Voting.Authorities]]             Identifier = "auth2"             IdentityPublicKey = "-----BEGIN ED25519 PUBLIC KEY-----\n60KQRhG7njt+kLQuwWlfRzJeOp4elM1/k26U/k52SjI=\n-----END ED25519 PUBLIC KEY-----\n"             PKISignatureScheme = "Ed25519"             LinkPublicKey = "-----BEGIN XWING PUBLIC KEY-----\nHVR2m7i6G6cf1qxUvyEr3KC7JvAMv5Or1rgzvUcllnmhN8BGmOmWhrWLggBNsyyS\nx+gbkfczC8WZr4GDAXOmGchhEYRy9opjqxEBENW9IHU>             WireKEMScheme = "xwing"             Addresses = ["127.0.0.1:30002"]              [[PKI.Voting.Authorities]]             Identifier = "auth3"             IdentityPublicKey = "-----BEGIN ED25519 PUBLIC KEY-----\naZUXqznyLO2mKDceIDs0obU6GAFZa3eKUDXo2RyWpBk=\n-----END ED25519 PUBLIC KEY-----\n"             PKISignatureScheme = "Ed25519"             LinkPublicKey = "-----BEGIN XWING PUBLIC KEY-----\nEZukXtZwHTjGj7tCI0kmUcq0QEtA4HMIz2OPiXQVeaK9XVBDNQUKq8iGRvzJAodM\nmJiEXYw6vvTJhPaik4OgMpZvwQYNn9BmwrcE7VxQfua>             WireKEMScheme = "xwing"             Addresses = ["127.0.0.1:30003"]
```

::: itemizedlist
-   [**Identifier**]{.bold}

    A human-readable identifier for the node, for example, an FQDN.

    Type: string

-   [**IdentityPublicKey**]{.bold}

    The public identity key in PEM format.

    Type: string

-   [**PKISignatureScheme**]{.bold}

    Specifies the cryptographic signature scheme

    Type: string

-   [**LinkPublicKey**]{.bold}

    The peer\'s public link-layer key in PEM format.

    Type: string

-   [**WireKEMScheme**]{.bold}

    Specifies the wire protocol KEM scheme.

    Type: string

-   [**Addresses**]{.bold}

    A list of IP address/port combinations that
    `<!--peer authority-->`{=html}
    `<!--author="dwrob" timestamp="20240814T170317-0700" comment="Should be &quot;the service node&quot;?"-->`{=html}peer
    authority uses for the Directory Authority service.

    Type: \[\]string
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#service-management-config}Management section {#management-section-2 .title}

</div>

</div>
:::

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/server/config/config.go#L729-->`{=html}

Management is the Katzenpost management interface configuration. The
management section specifies connectivity information for the Katzenpost
control protocol which can be used to make configuration changes during
run-time. An example configuration looks like this:

``` programlisting
[Management]     Enable = false     Path = "/voting_mixnet/mix1/management_sock"
```

::: itemizedlist
-   [**Enable**]{.bold}

    Enables the management interface if set to true.

    Type: bool

-   [**Path**]{.bold}

    Specifies the path to the management interface socket. `<!--If
                                left empty, then management_sock will be used under the DataDir.-->`{=html}
    `<!--author="dwrob" timestamp="20240814T171718-0700" comment="Confusing wording."-->`{=html}If
    left empty, then management_sock will be used under the DataDir.

    Type: string
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#service-sphinx-config}SphinxGeometry section {#sphinxgeometry-section-3 .title}

</div>

</div>
:::

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/core/sphinx/geo/geo.go#L40-->`{=html}

To do: Introduction

``` programlisting
[SphinxGeometry]     PacketLength = 3082     NrHops = 5     HeaderLength = 476     RoutingInfoLength = 410     PerHopRoutingInfoLength = 82     SURBLength = 572     SphinxPlaintextHeaderLength = 2     PayloadTagLength = 32     ForwardPayloadLength = 2574     UserForwardPayloadLength = 2000     NextNodeHopLength = 65     SPRPKeyMaterialLength = 64     NIKEName = "x25519"     KEMName = ""
```

::: itemizedlist
-   [**PacketLength**]{.bold}

    PacketLength is the total length of a Sphinx packet.

    Type: int

-   [**NrHops**]{.bold}

    NrHops is the number of permitted hops for a packet. This setting
    influences the size of the Sphinx packet header.

    Type: int

-   [**HeaderLength**]{.bold}

    HeaderLength is the length of the Sphinx packet header in bytes.

    Type: int

-   [**RoutingInfoLength**]{.bold}

    RoutingInfoLength is the length of the routing info portion of the
    Sphinx packet header.

    Type: int

-   [**PerHopRoutingInfoLength**]{.bold}

    PerHopRoutingInfoLength is the length of the per-hop routing info in
    the Sphinx packet header.

    Type: int

-   [**SURBLength**]{.bold}

    SURBLength is the length of SURB.

    Type: int

-   [**SphinxPlaintextHeaderLength**]{.bold}

    SphinxPlaintextHeaderLength is the length of the plaintext header.

    Type: int

-   [**PayloadTagLength**]{.bold}

    PayloadTagLength is the length of the payload tag.

    Type: int

-   [**ForwardPayloadLength**]{.bold}

    ForwardPayloadLength is the size of the payload.

    Type: int

-   [**UserForwardPayloadLength**]{.bold}

    The size of the Sphinx packet\'s usable payload.

    Type: int

-   [**NextNodeHopLength**]{.bold}

    NextNodeHopLength is derived from the largest routing info block
    that we expect to encounter. Everything else just has a
    NextNodeHop + NodeDelay, or a Recipient, both cases which are
    shorter.

    Type: int

-   [**SPRPKeyMaterialLength**]{.bold}

    SPRPKeyMaterialLength is the length of the SPRP key.

    Type: int

-   [**NIKEName**]{.bold}

    NIKEName is the name of the NIKE scheme used by the mixnet\'s Sphinx
    packet. NIKEName and KEMName are mutually exclusive.

    Type: string

-   [**KEMName**]{.bold}

    KEMName is the name of the KEM scheme used by the mixnet\'s Sphinx
    packets. NIKEName and KEMName are mutually exclusive.

    Type: string
:::
:::

::: section
::: titlepage
<div>

<div>

#### []{#service-debug-config}Debug section {#debug-section-3 .title}

</div>

</div>
:::

`<!--
                  https://github.com/katzenpost/katzenpost/blob/c255fbbf421d5d9820553c18dc5dc6c9881ad547/server/config/config.go-->`{=html}

The Katzenpost server debug configuration is used for advanced tuning.

``` programlisting
[Debug]                     NumSphinxWorkers = 16                     NumServiceWorkers = 3                     NumGatewayWorkers = 3                     NumKaetzchenWorkers = 3                     SchedulerExternalMemoryQueue = false                     SchedulerQueueSize = 0                     SchedulerMaxBurst = 16                     UnwrapDelay = 250                     GatewayDelay = 500                     ServiceDelay = 500                     KaetzchenDelay = 750                     SchedulerSlack = 150                     SendSlack = 50                     DecoySlack = 15000                     ConnectTimeout = 60000                     HandshakeTimeout = 30000                     ReauthInterval = 30000                     SendDecoyTraffic = false                     DisableRateLimit = false                     GenerateOnly = false
```

::: itemizedlist
`<!--
                     Worker "processes"?-->`{=html}

-   [**NumSphinxWorkers**]{.bold}

    Specifies the number of worker instances for processing inbound
    Sphinx packets.

    Type: int

-   [**NumProviderWorkers**]{.bold}

    Specifies the number of worker instances for processing
    provider-specific packets.

    Type: int

-   [**NumKaetzchenWorkers**]{.bold}

    Specifies the number of worker instances for processing
    Kaetzchen-specific packets.

    Type: int

-   [**SchedulerExternalMemoryQueue**]{.bold}

    If [**true**]{.bold}, enables the experimental external memory queue
    that is backed backed up to disk.

    Type: bool

-   [**SchedulerQueueSize**]{.bold}

    The maximum allowed scheduler queue size before random entries will
    start getting dropped. A value \<= 0 is treated as unlimited.

    Type: int

-   [**SchedulerMaxBurst**]{.bold}

    The maximum number of packets that will be dispatched per scheduler
    wakeup event.

    Type:

-   [**UnwrapDelay**]{.bold}

    The maximum allowed unwrap delay due to queueing, in milliseconds.

    Type: int

-   [**GatewayDelay**]{.bold}

    The maximum allowed gateway node worker delay due to queueing, in
    milliseconds.

    Type: int

-   [**ServiceDelay**]{.bold}

    The maximum allowed provider delay due to queueing, in milliseconds.

    Type: int

-   [**KaetzchenDelay**]{.bold}

    The maximum allowed kaetzchen delay due to queueing, in
    milliseconds.

    Type: int

-   [**SchedulerSlack**]{.bold}

    The maximum allowed scheduler slack due to queueing and/or
    processing, in milliseconds.

    Type: int

-   [**SendSlack**]{.bold}

    The maximum allowed send queue slack due to queueing and/or
    congestion, in milliseconds.

    Type: int

-   [**DecoySlack**]{.bold}[]{.bold}

    The maximum allowed decoy sweep slack due to various external
    delays, such as latency, before a loop decoy packet will be
    considered lost.

    Type: int

-   [**ConnectTimeout**]{.bold}

    Specifies the maximum time a connection can take to establish a
    TCP/IP connection, in milliseconds.

    Type: int

-   [**HandshakeTimeout**]{.bold}

    Specifies the maximum time a connection can take for a link protocol
    handshake, in milliseconds.

    Type: int

-   [**ReauthInterval**]{.bold}

    Specifies the interval after which a connection will be
    reauthenticated, in milliseconds.

    Type: int

-   [**SendDecoyTraffic**]{.bold}

    If [**true**]{.bold}, enables sending decoy traffic. Disabled by
    default.

    Type: bool

-   [**DisableRateLimit**]{.bold}

    If [**true**]{.bold}, disables the per-client rate limiter. This
    option should only be used for testing.

    Type: bool

-   [**GenerateOnly**]{.bold}

    If [**true**]{.bold}, halts and cleans up the server after long term
    key generation.

    Type: bool
:::
:::
:::
:::
:::
