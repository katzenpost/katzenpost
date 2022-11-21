Katzenpost Mix Server Infrastructure
====================================

Introduction
------------

A Katzenpost Provider is strictly a superset of the Katzenpost mix.
Both of these components are provided for by the ``server`` binary.
Each Provider and Mix MUST be white-listed by the Directory Authority (PKI)
in order to participate in the network.


Configuration
-------------


```
adduser --disabled-login --disabled-password --system --group --home /var/lib/katzenpost-authority katzenpost-authority
adduser --disabled-login --disabled-password --system --group --home /var/lib/katzenpost-mixserver katzenpost-mixserver
cat << EOF > /etc/systemd/system/katzenpost-authority.service
[Unit]
Description=Katzenpost Authority
After=network.target

[Service]
Type=simple
IPAccounting=yes
User=katzenpost-authority
WorkingDirectory=/var/lib/katzenpost-authority
ExecStart=/usr/local/bin/katzenpost-authority -f /etc/katzenpost-authority/authority.toml
PrivateTmp=yes
NoNewPrivileges=yes
Restart=on-failure

[Install]
WantedBy=default.target
EOF
cat << EOF > /etc/systemd/system/katzenpost-mixserver.service
[Unit]
Description=Katzenpost Mix Server
After=network.target

[Service]
IPAccounting=yes
Type=simple
User=katzenpost-mixserver
WorkingDirectory=/var/lib/katzenpost-mixserver
ExecStart=/usr/local/bin/katzenpost-mixserver -f /etc/katzenpost-mixserver/katzenpost.toml
PrivateTmp=yes
NoNewPrivileges=yes
# RestartSec=5
Restart=on-failure

[Install]
WantedBy=default.target
EOF
chmod 700 /var/lib/katzenpost-mixserver
chmod 700 /var/lib/katzenpost-authority
mkdir /etc/katzenpost-mixserver/
mkdir /etc/katzenpost-authority/
```

then, build yourself a katzenpost mix and authority binary


```
cd  /home/user/src/katzenpost/server/cmd/server/;
go build
cp /home/user/src/katzenpost/server/cmd/server/server /usr/local/bin/katzenpost-mixserver
cd /home/user/src/katzenpost/authority/cmd/voting
go build
cp /home/user/src/katzenpost/authority/cmd/voting/voting /usr/local/bin/katzenpost-authority
```

then restart systemd to see those services:

```
systemctl daemon-reload
systemctl start katzenpost-authority
systemctl start katzenpost-mixnet
```

then once it's working, i need to know your public keys

first start it

then, cat /var/lib/katzenpost-mixserver/identity.public.pem and /var/lib/katzenpost-authority/identity.public.pem and /var/lib/katzenpost-authority/link.public.pem

then, i need to add that to my config...

then we have another authority + mix
