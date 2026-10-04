#!/bin/sh
set -eu

for b in clientd config server dirauth courier replica genconfig \
         genkeypair geometry sphinx ping fetch echo-plugin \
         http-proxy-client http-proxy-server; do
    test -x "/usr/bin/kp$b" \
        || { printf '%s\n' "missing kp$b" >&2; exit 1; }
done
for p in $(dpkg-query -L katzenpost | grep '^/usr/bin/'); do
    case ${p#/usr/bin/} in
    kp*) ;;
    *) printf '%s\n' "$p is not prefixed with kp" >&2; exit 1 ;;
    esac
done
test -x /usr/bin/ping
dpkg-query -S /usr/bin/ping | grep -q iputils-ping

test -f /etc/katzenpost/kpclientd.toml
test -f /etc/katzenpost/thinclient.toml
for d in server authority replica; do
    test -d "/etc/katzenpost/$d" \
        || { printf '%s\n' "missing /etc/katzenpost/$d" >&2; exit 1; }
done
test -f /usr/lib/systemd/user/kpclientd.service
test -f /usr/lib/systemd/system/kpclientd.service
for u in kpserver kpauthority kpreplica; do
    test -f "/usr/lib/systemd/system/$u@.service" \
        || { printf '%s\n' "missing system unit $u@" >&2; exit 1; }
done
test -f /usr/lib/sysusers.d/katzenpost.conf
if command -v systemd-analyze >/dev/null; then
    systemd-analyze verify \
        /usr/lib/systemd/system/kpserver@.service \
        /usr/lib/systemd/system/kpauthority@.service \
        /usr/lib/systemd/system/kpreplica@.service \
        /usr/lib/systemd/system/kpclientd.service
fi

sys="/etc/systemd/system /usr/lib/systemd/system"
usr="/etc/systemd/user /usr/lib/systemd/user /root/.config/systemd/user"
for u in kpclientd kpserver kpauthority kpreplica; do
    want="*.wants/$u*.service"
    if find $sys $usr -path "$want" 2>/dev/null | grep -q .; then
        printf '%s\n' "error: $u is enabled" \
            "every katzenpost unit must be opt-in" >&2
        exit 1
    fi
done
