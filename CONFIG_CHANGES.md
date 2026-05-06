# Config file changes from v0.0.71 to main

This document enumerates the config-file changes between the v0.0.71
release tag and the current head of `main`. It is organised by component;
each component owns a TOML file and the schema is derived from a Go
`Config` struct in `<component>/config/config.go` (or analogous location).
Default-value changes that take effect even when the operator's TOML is
otherwise unchanged are noted at the bottom of each section.

The TOML field names below match the corresponding Go struct field
names exactly. Required actions for an operator upgrading from v0.0.71
are marked **[breaking]**; everything else is opt-in.

## Directory authority (`authority.toml`)

Source: `authority/voting/server/config/config.go`.

### `[Parameters]`

- **Added** `LambdaR` (float64). Inverse of the mean of the exponential
  distribution that the courier and storage replicas sample for
  decoy traffic between each other. Defaulted to `0.00025` if unset.
- **Added** `LambdaRMaxDelay` (uint64). Maximum delay for `LambdaR`,
  in milliseconds. Defaulted from `LambdaR` if unset.

### `[[StorageReplicas]]`

The replica entries are now their own table type rather than re-using
the `[[Mixes]]`/`[[GatewayNodes]]`/`[[ServiceNodes]]` `Node` shape.

- **Added** `ReplicaID` (uint8). **[breaking]** A static identifier
  unique within the replica set. Every dirauth must agree on the same
  `ReplicaID` for each replica's `IdentityPublicKeyPem`. Without this
  field the dirauth refuses to start (`config: StorageReplicaNode is
  missing ...`) or rejects the descriptor on consensus.

  Example:

  ```toml
  [[StorageReplicas]]
    Identifier = "replica1"
    IdentityPublicKeyPem = "../replica1/identity.public.pem"
    ReplicaID = 0
  ```

### `[[Authorities]]`

No TOML-visible changes. The Go type of `LinkPublicKey` was wrapped in
a new `LinkPublicKey` struct so that BurntSushi/toml can serialise it
back to PEM via `MarshalText`; the on-disk encoding is unchanged.

### `[Server]` defaults

- `HandshakeTimeoutSec` default raised from `60` to `180`. Operators
  who left this at `0` (default) will see the longer timeout.

### Removed fields

None.

## Mix server, gateway, and service node (`katzenpost.toml`)

Source: `server/config/config.go`.

### `[Server.Gateway]`

- **Removed** `[Gateway.UserDB]` table (and its `[Gateway.UserDB.Bolt]`
  and `[Gateway.UserDB.Extern]` inner tables). **[breaking]** Old
  configs that included these will fail to decode. The userdb backend
  has been removed entirely.
- **Removed** `[Gateway.SQLDB]` table. **[breaking]** SQL-backed
  storage is no longer supported. Only the BoltDB spool (`[Gateway.SpoolDB.Bolt]`)
  remains.

### Defaults

- `defaultSchedulerSlack` raised from `150` to `450` ms.
- `defaultHandshakeTimeout` raised from `60` to `180` seconds.

### Removed fields

- The exported constants `BackendSQL` and `BackendExtern` are gone.
  Operators using `Backend = "sql"` or `Backend = "extern"` in either
  the SpoolDB or UserDB tables must drop those settings; only `"bolt"`
  is now valid.

## Replica (`replica.toml`)

Source: `replica/config/config.go`.

### Top level

- **Added** `ReplicaID` (uint8). **[breaking]** Must match the
  corresponding `ReplicaID` in every dirauth's `[[StorageReplicas]]`
  entry for this replica.
- **Added** `IncomingQueueSize` (int). Buffer size for the incoming
  connection sender queue. Defaults to `1000`.
- **Added** `MaxConcurrentReplications` (int). Concurrency cap on
  replication operations to shard members. Defaults to `4`.
- **Added** `ProxyRequestTimeout` (int). Timeout in seconds for proxy
  requests to other replicas. Defaults to `300` (5 minutes).
- **Added** `ProxyWorkerCount` (int). Number of goroutines that handle
  proxy requests concurrently. Defaults to `8`.
- **Added** `MetricsAddress` (string). Address/port for the Prometheus
  metrics endpoint, e.g. `"127.0.0.1:33001"`. Empty disables the
  listener. Validated with `net/netip`.
- **Removed** `ReplicationQueueLength` (int). **[breaking]** No longer
  consumed; remove from existing TOML.

## Courier (`courier.toml`)

Source: `courier/server/config/config.go`.

### Top level

- **Added** `MetricsAddress` (string). Address/port for the Prometheus
  metrics endpoint. Empty disables the listener.

No removals or breaking changes.

## Client daemon, kpclientd (`client.toml`)

Source: `client/config/config.go`.

The client TOML had the most substantial reshape, driven by the
`client2 → client` rename and the new transport-abstraction layer.

### Top level

- **Added** `[Listen]`. **[breaking]** Required. The daemon's
  thin-client listen socket configuration. The table is
  subtable-discriminated; exactly one of its inner subtables must be
  populated:

  ```toml
  [Listen]
    [Listen.Tcp]
      Address = "localhost:64331"
      Network = "tcp"
  ```

  or:

  ```toml
  [Listen]
    [Listen.Unix]
      Address = "/var/run/katzenpost/kpclientd.sock"
  ```

- **Added** `PigeonholeGeometry` (table). Pigeonhole protocol
  parameters; required for new pigeonhole channel operations.

- **Added** `[CachedDocument]`. Optional. Holds a serialised PKI
  document so the client can connect to its pinned gateway without
  contacting an authority on first start.

- **Added** `[PinnedGateways]` with repeating `[[PinnedGateways.Gateways]]`
  entries. Each entry has `WireKEMScheme`, `Name`, `IdentityKey`,
  `LinkKey`, `PKISignatureScheme`, and `Addresses`. The `IdentityKey`
  and `LinkKey` are PEM-encoded inline.

- **Removed** `RatchetNIKEScheme` (string). **[breaking]** No longer
  consumed; remove from existing TOML.

### `[Debug]`

- **Added** `EnableTimeSync` (bool). Use skewed remote provider time
  instead of system time when available.
- **Removed** `PreferedTransports` ([]string). **[breaking]** No
  longer consumed; remove from existing TOML.

### `[[VotingAuthority.Peers]]` and the new `[[PinnedGateways.Gateways]]`

The `LinkPublicKey` (in `VotingAuthority.Peers`) and `LinkKey` (in
`PinnedGateways.Gateways`) Go types were wrapped in a `LinkPublicKey`
struct so BurntSushi/toml can serialise them back to PEM via
`MarshalText`; the on-disk PEM encoding is unchanged.

## Thin client (`thinclient.toml`)

Source: `client/thin/thin.go`, `Config` type.

### Top level

- **Removed** `Network` (string) and `Address` (string). **[breaking]**
  Both top-level fields are gone.
- **Added** `[Dial]`. **[breaking]** Required. Mirrors the daemon's
  `[Listen]` subtable shape; exactly one of `[Dial.Unix]` or
  `[Dial.Tcp]` must be populated:

  ```toml
  [Dial]
    [Dial.Tcp]
      Address = "localhost:64331"
      Network = "tcp"
  ```

  or:

  ```toml
  [Dial]
    [Dial.Unix]
      Address = "/var/run/katzenpost/kpclientd.sock"
  ```

`SphinxGeometry` and `PigeonholeGeometry` remain as before.

## PKI document format (informational)

This is not a config-file change but consequences propagate to
operators: the signed PKI document version was bumped from `v0` to
`v1` because new fields (`LambdaR`, `LambdaRMaxDelay`,
`ConfiguredReplicaIdentityKeys`, `ReplicaEnvelopeKeys`) are now
present. v0 readers will refuse a v1 document via the
`ParseDocument` version check rather than deserialise it incorrectly.
All clients, dirauths, mix nodes, replicas, and couriers must run
the matching code base; mixed-version networks are not supported.

## Common defaults

Source: `common/config/config.go`. These values are inherited by
several components.

- `DefaultHandshakeTimeout` raised from `60` to `180` seconds.
- `DefaultConnectTimeout` and `DefaultReauthInterval` unchanged.
