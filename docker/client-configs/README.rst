namenlos client config
======================

``make client-check`` reads ``namenlos.toml`` (the client config) and
``namenlos-thin.toml`` (the thin-client dial config) here. Both are the public
katzenpost client configuration for namenlos, the same files the katzenqt client
ships, and hold public keys only; never add a server, authority, or replica
config. ``client-check`` rewrites the daemon socket to a private name before
use, so it does not collide with a running katzenqt. Override the client config
with ``namenlos_config=<path>``.
