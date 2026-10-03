GO_VERSION := 1.27.1

DEB_DISTROS ?= debian-13 debian-forky ubuntu-24.04 ubuntu-26.04

.PHONY: deb deb-build deb-ci deb-test deb-image-ref deb-image \
	deb-image-push deb-image-refs

deb:
	@$(MAKE) -C packaging/debian -f container.mk

deb-build:
	@packaging/debian/build.sh

deb-ci:
	@packaging/debian/ci.sh

deb-test:
	@packaging/debian/test.sh

deb-image-ref:
	@packaging/container/deb-image.sh --ref $(DISTRO)

deb-image-refs:
	@for d in $(DEB_DISTROS); do \
		key=$$(printf '%s' "$$d" | tr '.-' '__'); \
		printf 'ref_%s=%s\n' "$$key" \
			"$$(packaging/container/deb-image.sh --ref $$d)"; \
	done

deb-image:
	@packaging/container/deb-image.sh --ensure $(DISTRO)

deb-image-push:
	@packaging/container/deb-image.sh --push $(DISTRO)
