#!/usr/bin/env bash

set -eux

TMPDIR="$(mktemp -d /tmp/prime.XXXXXXXX)"
PUBKEY="${TMPDIR}"/pubkey
PRIKEY="${TMPDIR}"/prikey
CIPHER="${TMPDIR}"/cipher

cleanup() {
	rm -f "${PUBKEY}"
	rm -f "${PRIKEY}"
	rm -f "${CIPHER}"
	rmdir "${TMPDIR}"
	exit
}

trap cleanup EXIT

for i in encap decap keygen; do
	(cd examples/$i && go build)
done

for i in 1 2 3 4 5; do
	./examples/keygen/keygen /dev/urandom "${PUBKEY}" "${PRIKEY}"
	for j in 1 2 3; do
		x="$(./examples/encap/encap /dev/urandom ${PUBKEY} ${CIPHER})"
		y="$(./examples/decap/decap ${PRIKEY} ${CIPHER})"
		[ "${x}" == "${y}" ]
		rm "${CIPHER}"
	done
	rm "${PUBKEY}" "${PRIKEY}"
done
