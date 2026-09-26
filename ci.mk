# SPDX-License-Identifier: AGPL-3.0-only

CONTAINER_ENGINE?=podman
ACT?=act
FORGEJO_RUNNER?=forgejo-runner
RUNNER?=
CI_RUNNERS?=act forgejo-runner woodpecker-cli
WOODPECKER?=woodpecker-cli
CI_WORKFLOWS_WOODPECKER?=.woodpecker
CI_WOODPECKER_BACKEND?=docker
CI_WOODPECKER_ARGS?=--local --backend-engine $(CI_WOODPECKER_BACKEND)

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
	@runner="$(RUNNER)"; \
	if [ -z "$$runner" ]; then \
	  for candidate in $(CI_RUNNERS); do \
	    command -v "$$candidate" >/dev/null 2>&1 && { runner="$$candidate"; break; }; \
	  done; \
	fi; \
	case "$$runner" in \
	  act) $(ACT) $(CI_ACT_ARGS) -P $(CI_PLATFORM) --container-options "$(CI_RUN_OPTIONS)" \
	    $(if $(CI_WORKFLOW),-W $(CI_WORKFLOWS_ACT)/$(CI_WORKFLOW),-W $(CI_WORKFLOWS_ACT)) $(if $(CI_JOB),-j $(CI_JOB),);; \
	  forgejo|forgejo-runner) $(FORGEJO_RUNNER) exec $(CI_FORGEJO_ARGS) -P $(CI_PLATFORM) --container-options "$(CI_RUN_OPTIONS)" \
	    $(if $(CI_WORKFLOW),-W $(CI_WORKFLOWS_FORGEJO)/$(CI_WORKFLOW),-W $(CI_WORKFLOWS_FORGEJO)) $(if $(CI_JOB),-j $(CI_JOB),);; \
	  woodpecker|woodpecker-cli) set -e; for pipeline in $(if $(CI_WORKFLOW),$(CI_WORKFLOWS_WOODPECKER)/$(CI_WORKFLOW),$(CI_WORKFLOWS_WOODPECKER)/*.yaml); do \
	    DOCKER_HOST="unix://$(CI_SOCKET)" $(WOODPECKER) exec $(CI_WOODPECKER_ARGS) --repo-path "$(CURDIR)" "$$pipeline"; done;; \
	  "") echo "no local ci runner found; install one of: $(CI_RUNNERS)" >&2; exit 1;; \
	  *) echo "RUNNER must be act, forgejo or woodpecker" >&2; exit 1;; \
	esac
