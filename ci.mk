# SPDX-License-Identifier: AGPL-3.0-only

CONTAINER_ENGINE?=podman
ACT?=act
FORGEJO_RUNNER?=forgejo-runner
RUNNER?=act

CI_IMAGE_NAME?=katzenpost-ci
CI_IMAGE_TAG?=latest
CI_IMAGE_DOCKERFILE?=.ci/Dockerfile
CI_IMAGE_LOCAL?=localhost/$(CI_IMAGE_NAME):$(CI_IMAGE_TAG)
CI_IMAGE_DIGEST?=
CI_IMAGE?=$(if $(CI_IMAGE_DIGEST),$(CI_IMAGE_DIGEST),$(CI_IMAGE_LOCAL))
CI_REGISTRIES?=

CI_PLATFORM?=ubuntu-latest=$(CI_IMAGE)
CI_WORKFLOWS_ACT?=.github/workflows
CI_WORKFLOWS_FORGEJO?=.forgejo/workflows
CI_WORKFLOW?=
CI_JOB?=
CI_SOCKET?=/run/user/$(shell id -u)/podman/podman.sock
CI_RUN_OPTIONS?=-v /etc/ssl/certs:/etc/ssl/certs:ro -v $(CI_SOCKET):/var/run/docker.sock
CI_ACT_ARGS?=--bind --rm --concurrent-jobs 1
CI_FORGEJO_ARGS?=--bind

.PHONY: ci-local ci-local-image ci-local-image-push ci-local-image-shell

ci-local-image:
	@if [ -n "$(CI_IMAGE_DIGEST)" ]; then \
	  $(CONTAINER_ENGINE) pull $(CI_IMAGE_DIGEST); \
	else \
	  $(CONTAINER_ENGINE) build -t $(CI_IMAGE_LOCAL) -f $(CI_IMAGE_DOCKERFILE) .; \
	fi

ci-local-image-push: ci-local-image
	@test -n "$(CI_REGISTRIES)" || { echo "set CI_REGISTRIES to one or more registry prefixes" >&2; exit 1; }
	@set -e; for registry in $(CI_REGISTRIES); do \
	  $(CONTAINER_ENGINE) tag $(CI_IMAGE_LOCAL) $$registry/$(CI_IMAGE_NAME):$(CI_IMAGE_TAG); \
	  $(CONTAINER_ENGINE) push $$registry/$(CI_IMAGE_NAME):$(CI_IMAGE_TAG); \
	done

ci-local-image-shell: ci-local-image
	$(CONTAINER_ENGINE) run --rm -it --network host -v "$(CURDIR):$(CURDIR)" -w "$(CURDIR)" --entrypoint /bin/bash $(CI_IMAGE)

ci-local: ci-local-image
	@case "$(RUNNER)" in \
	  act) $(ACT) $(CI_ACT_ARGS) -P $(CI_PLATFORM) --container-options "$(CI_RUN_OPTIONS)" \
	    $(if $(CI_WORKFLOW),-W $(CI_WORKFLOWS_ACT)/$(CI_WORKFLOW),-W $(CI_WORKFLOWS_ACT)) $(if $(CI_JOB),-j $(CI_JOB),);; \
	  forgejo) $(FORGEJO_RUNNER) exec $(CI_FORGEJO_ARGS) -P $(CI_PLATFORM) --container-options "$(CI_RUN_OPTIONS)" \
	    $(if $(CI_WORKFLOW),-W $(CI_WORKFLOWS_FORGEJO)/$(CI_WORKFLOW),-W $(CI_WORKFLOWS_FORGEJO)) $(if $(CI_JOB),-j $(CI_JOB),);; \
	  *) echo "RUNNER must be act or forgejo" >&2; exit 1;; \
	esac
