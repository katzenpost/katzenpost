# kpclientd socket activation

These systemd user units start kpclientd on the first connection to the
per-user socket `$XDG_RUNTIME_DIR/katzenpost/kpclientd.sock`. systemd
creates the socket, mode 0600 in a 0700 directory, and passes it to
kpclientd in `LISTEN_FDS`; kpclientd serves on it instead of binding that
address. A thin client that connects before kpclientd runs waits in the
socket's queue and completes its handshake once the daemon accepts, so
the service needs no readiness notification and is `Type=simple`. The
socket outlives a crash or restart of the service.

## Config

The socket's path must be one of the `[Listen.Unix]` addresses, written
out in full. kpclientd does not expand variables in the config, so put
the value of `$XDG_RUNTIME_DIR` in its place, for example for uid 1000:

    [Listen]
      [Listen.Unix]
        Address = "@katzenpost"
        Addresses = ["/run/user/1000/katzenpost/kpclientd.sock"]

kpclientd binds the addresses systemd does not pass, here `@katzenpost`,
itself. It refuses to start when systemd passes a socket that no
`[Listen.Unix]` address names, or passes any socket to a `[Listen.Tcp]`
or `[Listen.Ws]` config, rather than serve where the config does not
say. `Accept=yes` sockets are not supported.

## Enable

    mkdir -p ~/.config/systemd/user ~/.config/katzenpost
    cp kpclientd.socket kpclientd.service ~/.config/systemd/user/
    cp /path/to/client.toml ~/.config/katzenpost/kpclientd.toml
    systemctl --user daemon-reload
    systemctl --user enable --now kpclientd.socket

Enable only the socket; the first connection starts kpclientd.service.
The service expects the binary at /usr/bin/kpclientd; edit ExecStart for
another install. `systemctl --user stop kpclientd.socket kpclientd.service`
stops both. While the socket unit holds the path, a kpclientd started by
hand with the same config fails with address in use, which keeps a
second instance out.
