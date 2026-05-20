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

## A note on decoding behaviour

Every component except the thin client decodes its TOML with
BurntSushi's `toml.Unmarshal`, which is lenient: a key or table that no
longer maps to a Go struct field is silently ignored, not rejected. A
config carrying a **removed** field therefore still loads; the field
simply has no effect. The required operator action for a removed field
is housekeeping (delete the dead lines so the file reflects reality),
not an emergency: leaving it in place will not stop the daemon.

The genuine hard failures are narrower and are called out explicitly
where they occur:

- **validation requirements**: a field whose *absence* fails
  `FixupAndValidate`, e.g. the client daemon's `[Listen]`.
- **the thin client's strict check**: `thinclient.toml` is decoded with
  `toml.NewDecoder(...).Decode` followed by a `MetaData.Undecoded()`
  check, so an unknown or stale key there *is* rejected at load.
- **semantic collisions**: a field that decodes cleanly but whose value
  is then rejected by a consistency rule, e.g. duplicate replica
  `ReplicaID`.

"**[breaking]**" below means "the operator must act to preserve
previous behaviour or to satisfy a new requirement", which is not
always the same as "the file fails to parse".

## Directory authority (`authority.toml`)

Source: `authority/voting/server/config/config.go`.

### `[Parameters]`

- **Added** `LambdaR` (float64). Inverse of the mean of the exponential
  distribution that the courier and storage replicas sample for
  decoy traffic between each other. Defaulted to `0.00025` if unset.
- **Added** `LambdaRMaxDelay` (uint64). Maximum delay for `LambdaR`,
  in milliseconds. Defaulted from `LambdaR` if unset.
- **Removed** `SendRatePerMinute` (uint64). The gateway daemon now
  derives its per-client token-bucket parameters internally on every
  PKI-document update from `doc.LambdaP + doc.LambdaL`, with a
  10 percent refill headroom and a bucket cap of 256. No operator
  surface is exposed; the consensus document publishes the rates,
  the gateway enforces them. A stale `SendRatePerMinute` line in the
  authority TOML is silently ignored by the lenient loader (and the
  field is also no longer carried in the signed PKI document; see
  the PKI document section).
- **Removed** `LambdaD` (float64) and `LambdaDMaxDelay` (uint64).
  These governed the now-retired drop-decoy Poisson process; the
  client collapsed to a two-ticker model (`LambdaP` for
  message-or-loop-decoy, `LambdaL` for loop-decoy-only) and no
  client code samples `LambdaD` any more. Silently ignored if left
  in `authority.toml`.
- **Changed semantics** `LambdaG` (float64). Still decoded by
  BurntSushi but now overridden by an internally computed value: the
  dirauth derives `LambdaG` from the number of gateway nodes and the
  other lambdas, so any value set in TOML has no effect. The field
  carries an in-source `WARNING` comment to that effect. Remove from
  existing files as housekeeping; `LambdaGMaxDelay` is still
  operator-set and is validated as non-zero.

### `[[StorageReplicas]]`

The replica entries are now their own table type rather than re-using
the `[[Mixes]]`/`[[GatewayNodes]]`/`[[ServiceNodes]]` `Node` shape.

- **Added** `ReplicaID` (uint8). **[breaking]** A static identifier
  unique within the replica set. Every dirauth, and the replica itself,
  must agree on the same `ReplicaID` for each replica's
  `IdentityPublicKeyPem`. The field is not checked by
  `StorageReplicaNode.validate()` (which only rejects a missing
  `Identifier` or `IdentityPublicKeyPem`), and uint8 has no
  distinguished "unset" value: an omitted `ReplicaID` decodes as `0`.
  The breaking effect is therefore semantic, not a decode error. If
  more than one replica omits the field they collide on `0` and
  `FixupAndValidate` fails with `config: Storage Replica Node:
  ReplicaID '0' is used by both '<a>' and '<b>'`; and a `ReplicaID`
  that decodes cleanly but disagrees with the value the replica and the
  other dirauths use yields an inconsistent consensus and misrouted
  shards rather than a startup error. Set it explicitly on every
  replica entry.

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
  and `[Gateway.UserDB.Extern]` inner tables). **[breaking]** The userdb
  backend has been removed entirely. The server `Gateway` struct now
  exposes only `SpoolDB`, so a stale `[Gateway.UserDB]` table is
  silently ignored at load (BurntSushi is lenient); the operator action
  is to delete it, since the functionality it configured is gone.
- **Removed** `[Gateway.SQLDB]` table. **[breaking]** SQL-backed
  storage is no longer supported; only the BoltDB spool
  (`[Gateway.SpoolDB.Bolt]`) remains. As above, a leftover
  `[Gateway.SQLDB]` table is silently ignored rather than rejected, so
  the operator must remove it to regain a config that reflects reality.

### `[Debug]`

The "provider" worker pool was split into separate gateway and service
pools, and the corresponding `[Debug]` knobs were renamed accordingly.

- **Removed** `NumProviderWorkers` (int). **[breaking]** Replaced by
  `NumServiceWorkers` and `NumGatewayWorkers`, each defaulting to `3`.
  A config that still sets `NumProviderWorkers` is silently ignored, so
  the value no longer takes effect: an operator who had tuned this must
  re-express the intent under the two new keys.
- **Removed** `ProviderDelay` (int). **[breaking]** Replaced by
  `GatewayDelay` and `ServiceDelay`, each defaulting to `500` ms, with
  the same silent-ignore caveat as above.

### Defaults

- `defaultSchedulerSlack` raised from `150` to `450` ms.
- `defaultHandshakeTimeout` raised from `60` to `180` seconds.

### Removed fields

- The exported constants `BackendSQL` and `BackendExtern` are gone.
  Operators using `Backend = "sql"` or `Backend = "extern"` in either
  the SpoolDB or UserDB tables must drop those settings; only `"bolt"`
  is now valid.

### Management socket commands

Not a TOML change, but operator-visible. The thwack handlers
`SEND_RATE` and `SEND_BURST` have both been removed from the gateway
daemon. The management socket is intended for emergency live
overrides only; the per-client rate limit is now derived entirely
from the consensus document's `LambdaP` and `LambdaL` and applied at
each PKI-document update, with no operator action required. Scripts
that issued `SEND_RATE <n>` or `SEND_BURST <n>` against
`/var/lib/katzenpost/management_sock` will receive a "command not
found" error from thwack and should be retired.

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
- **Added** `MaxStorageMiB` (int64). Optional hard quota on the
  replica database's on-disk size in mebibytes (RocksDB live SST
  footprint). Writes that would exceed it are rejected with
  `ReplicaErrorStorageFull`. Defaults to `0`, meaning no database-size
  quota; only the filesystem reserve below applies. Must not be
  negative. (Renamed from `MaxStorageBytes` during the v0.0.71→main
  window; the units are now operator-friendly MiB rather than raw
  bytes. A stale `MaxStorageBytes` is silently ignored by the lenient
  loader.)
- **Added** `MinFreeStorageMiB` (int64). Filesystem free-space
  reserve on the `DataDir` filesystem in mebibytes: new writes are
  rejected with `ReplicaErrorStorageFull` once fewer than this many
  MiB remain available, regardless of `MaxStorageMiB`. `0` selects
  the 500 MiB default; a positive value overrides it. Must not be
  negative. Tombstones (deletions) are never gated by either limit,
  so a full replica can still be reclaimed. (Renamed from
  `MinFreeStorageBytes` for the same units-friendliness reason; the
  stale name is silently ignored.)
- **Removed** `ReplicationQueueLength` (int). No longer consumed. The
  replica decodes via the lenient common loader, so a leftover
  `ReplicationQueueLength` is silently ignored and does not block
  startup; remove it from existing TOML as housekeeping.

### Defaults

- With `MinFreeStorageMiB` unset, a replica now stops accepting new
  writes once its `DataDir` filesystem has under 500 MiB free. This
  takes effect even if the operator's TOML is otherwise unchanged.
  Previously writes were accepted until the disk filled and the
  condition surfaced only as transient database errors that clients
  retried. Set `MinFreeStorageMiB` and/or `MaxStorageMiB` to tune.

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

- **Removed** `RatchetNIKEScheme` (string). No longer consumed. The
  client daemon decodes with the lenient `toml.Unmarshal`, so a
  leftover `RatchetNIKEScheme` is silently ignored rather than rejected;
  remove it from existing TOML as housekeeping. (The genuinely breaking
  client change is the now-required `[Listen]`, above.)

### `[Debug]`

- **Added** `EnableTimeSync` (bool). Use skewed remote provider time
  instead of system time when available.
- **Removed** `PreferedTransports` ([]string). No longer consumed, and
  silently ignored by the lenient client decoder rather than rejected;
  remove it from existing TOML as housekeeping.

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

- **Removed** `[SphinxGeometry]` and `[PigeonholeGeometry]`.
  **[breaking]** Both sections are gone from `thinclient.toml`; only
  `[Dial]` remains. The daemon now delivers both geometries to the
  thin client over the handshake (in its `ConnectionStatusEvent`),
  exposed via `GetSphinxGeometry()` and `GetPigeonholeGeometry()`.
  genconfig no longer writes them into the generated file. A config
  that still carries either section is rejected at load (unknown-key
  check), and a daemon that omits the geometries is rejected at
  `Dial`. This removes the foot-gun of a thin-client geometry drifting
  silently out of step with the daemon's.

## PKI document format (informational)

This is not a config-file change but consequences propagate to
operators: the signed PKI document version was bumped from `v0` to
`v1` because new fields (`LambdaR`, `LambdaRMaxDelay`,
`ConfiguredReplicaIdentityKeys`, `ReplicaEnvelopeKeys`) are now
present. v0 readers will refuse a v1 document via the
`ParseDocument` version check rather than deserialise it incorrectly.
All clients, dirauths, mix nodes, replicas, and couriers must run
the matching code base; mixed-version networks are not supported.

Two further field removals after the version bump:

- `SendRatePerMinute` (uint64). Gone from `core/pki/document.go`;
  gateway daemons now derive their per-client token-bucket parameters
  from `LambdaP` and `LambdaL` locally rather than reading the
  consensus document's published cap. Older code paths that read the
  field will see zero (the Go zero value when the CBOR decoder finds
  no matching key), which matches the historical "rate limit
  disabled" semantics and degrades gracefully.

- `LambdaD` (float64). Gone for the same reason as in the dirauth
  `[Parameters]`: drop decoys are retired and the client samples no
  separate `LambdaD` process.

Neither removal triggers a further version bump; CBOR decoding of a
field absent from the wire payload yields the type's zero value, and
no code now depends on either field being present.

## Common defaults

Source: `common/config/config.go`. These values are inherited by
several components.

- `DefaultHandshakeTimeout` raised from `60` to `180` seconds.
- `DefaultConnectTimeout` and `DefaultReauthInterval` unchanged.
