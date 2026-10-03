PODMAN ?= podman
DISTRO ?= debian-13
DISTROS ?= debian-13 ubuntu-26.04

.PHONY: container container-all

container:
	@../container/build.sh $(DISTRO)

container-all:
	@for d in $(DISTROS); do ../container/build.sh $$d; done
