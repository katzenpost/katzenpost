# SPDX-License-Identifier: AGPL-3.0-only

CONTAINER_ENGINE?=podman
ACT?=act
FORGEJO_RUNNER?=forgejo-runner
RUNNER?=
CI_RUNNERS?=act forgejo-runner woodpecker-cli
WOODPECKER?=woodpecker-cli
ci_make=$(MAKE) -f $(firstword $(MAKEFILE_LIST))
CI_WORKFLOWS_WOODPECKER?=.woodpecker
CI_WOODPECKER_BACKEND?=docker
CI_WOODPECKER_ARGS?=--local --backend-engine $(CI_WOODPECKER_BACKEND)

CI_IMAGE_NAME?=katzenpost-ci
CI_IMAGE_TAG?=latest
CI_IMAGE_DOCKERFILE?=.ci/Dockerfile
CI_IMAGE_TMPDIR?=/var/tmp
CI_IMAGE_LOCAL?=localhost/$(CI_IMAGE_NAME):$(CI_IMAGE_TAG)
CI_IMAGE_DIGEST?=
CI_IMAGE_PULL?=
CI_IMAGE?=$(if $(CI_IMAGE_DIGEST),$(CI_IMAGE_DIGEST),$(CI_IMAGE_LOCAL))
CI_REGISTRIES?=

CI_PLATFORM?=ubuntu-latest=$(CI_IMAGE)
CI_WORKFLOWS_ACT?=.github/workflows
CI_WORKFLOWS_FORGEJO?=.forgejo/workflows
CI_WORKFLOW?=
CI_WORKFLOW_ACT?=linux.yml
CI_WORKFLOW_FORGEJO?=ci.yml
CI_WORKFLOWS_WOODPECKER_DEFAULT?=test.yaml check.yaml
CI_JOB?=
CI_SOCKET?=/run/user/$(shell id -u)/podman/podman.sock
CI_RUN_OPTIONS?=-v /etc/ssl/certs:/etc/ssl/certs:ro
CI_DAEMON_SOCKET?=unix://$(CI_SOCKET)
CI_ACT_ARGS?=--bind --rm --concurrent-jobs 1 --pull=false
CI_FORGEJO_ARGS?=

.PHONY: ci-local ci-local-run ci-local-image ci-local-image-push ci-local-image-shell

ci-local-image:
	@if [ -n "$(CI_IMAGE_DIGEST)" ]; then \
	  $(CONTAINER_ENGINE) pull $(CI_IMAGE_DIGEST); \
	  $(CONTAINER_ENGINE) tag $(CI_IMAGE_DIGEST) $(CI_IMAGE_LOCAL); \
	elif [ -n "$(CI_IMAGE_PULL)" ]; then \
	  $(CONTAINER_ENGINE) pull $(CI_IMAGE_PULL); \
	  $(CONTAINER_ENGINE) tag $(CI_IMAGE_PULL) $(CI_IMAGE_LOCAL); \
	else \
	  TMPDIR=$(CI_IMAGE_TMPDIR) $(CONTAINER_ENGINE) build -t $(CI_IMAGE_LOCAL) -f $(CI_IMAGE_DOCKERFILE) .; \
	fi

ci-local-image-push: ci-local-image
	@test -n "$(CI_REGISTRIES)" || { echo "set CI_REGISTRIES to one or more registry prefixes" >&2; exit 1; }
	@set -e; for registry in $(CI_REGISTRIES); do \
	  $(CONTAINER_ENGINE) tag $(CI_IMAGE_LOCAL) $$registry/$(CI_IMAGE_NAME):$(CI_IMAGE_TAG); \
	  $(CONTAINER_ENGINE) push $$registry/$(CI_IMAGE_NAME):$(CI_IMAGE_TAG); \
	done

ci-local-image-shell: ci-local-image
	$(CONTAINER_ENGINE) run --rm -it --network host -v "$(CURDIR):$(CURDIR)" -w "$(CURDIR)" \
	  -v "$(CI_SOCKET):$(CI_SOCKET)" -e DOCKER_HOST="$(CI_DAEMON_SOCKET)" \
	  --entrypoint /bin/bash $(CI_IMAGE)

# On exit, stop only the testnets this run brought up; one that was already
# running before the run is left alone.
ci-local-run:
	@up_before=" $$(echo docker/mixnet-*/running.stamp) "; \
	trap 'for d in docker/mixnet-*/; do d=$${d%/}; \
	  case "$$up_before" in *" $$d/running.stamp "*) continue;; esac; \
	  if [ -d "$$d" ]; then $(MAKE) -C docker distro=$${d#docker/mixnet-} stop >/dev/null 2>&1 || true; fi; \
	done' EXIT; \
	trap 'exit 130' INT; trap 'exit 143' TERM; \
	runner="$(RUNNER)"; \
	if [ -z "$$runner" ]; then \
	  for candidate in $(CI_RUNNERS); do \
	    command -v "$$candidate" >/dev/null 2>&1 && { runner="$$candidate"; break; }; \
	  done; \
	fi; \
	case "$$runner" in \
	  act) DOCKER_HOST="unix://$(CI_SOCKET)" $(ACT) $(CI_ACT_ARGS) -P $(CI_PLATFORM) --var CI_IMAGE=$(CI_IMAGE) --container-daemon-socket "$(CI_DAEMON_SOCKET)" --container-options "$(CI_RUN_OPTIONS)" \
	    -W $(CI_WORKFLOWS_ACT)/$(if $(CI_WORKFLOW),$(CI_WORKFLOW),$(CI_WORKFLOW_ACT)) $(if $(CI_JOB),-j $(CI_JOB),);; \
	  forgejo|forgejo-runner) DOCKER_HOST="unix://$(CI_SOCKET)" $(FORGEJO_RUNNER) exec $(CI_FORGEJO_ARGS) -i $(CI_IMAGE) --var CI_IMAGE=$(CI_IMAGE) --container-daemon-socket "$(CI_DAEMON_SOCKET)" --container-opts "$(CI_RUN_OPTIONS)" \
	    -W $(CI_WORKFLOWS_FORGEJO)/$(if $(CI_WORKFLOW),$(CI_WORKFLOW),$(CI_WORKFLOW_FORGEJO)) $(if $(CI_JOB),-j $(CI_JOB),);; \
	  woodpecker|woodpecker-cli) set -e; for pipeline in $(if $(CI_WORKFLOW),$(CI_WORKFLOWS_WOODPECKER)/$(CI_WORKFLOW),$(addprefix $(CI_WORKFLOWS_WOODPECKER)/,$(CI_WORKFLOWS_WOODPECKER_DEFAULT))); do \
	    DOCKER_HOST="unix://$(CI_SOCKET)" $(WOODPECKER) exec $(CI_WOODPECKER_ARGS) --repo-path "$(CURDIR)" "$$pipeline"; done;; \
	  "") echo "no ci runner found; install one of: $(CI_RUNNERS)" >&2; exit 1;; \
	  *) echo "RUNNER must be act, forgejo or woodpecker" >&2; exit 1;; \
	esac

ci-local: ci-local-image
	@for candidate in $(if $(RUNNER),$(RUNNER),$(CI_RUNNERS)); do \
	  command -v "$$candidate" >/dev/null 2>&1 && { \
	    exec $(ci_make) ci-local-run RUNNER="$$candidate"; }; \
	done; \
	echo "no ci runner on this host; using the one in $(CI_IMAGE)"; \
	exec $(CONTAINER_ENGINE) run --rm --network host \
	  -v "$(CURDIR):$(CURDIR)" -w "$(CURDIR)" \
	  -v "$(CI_SOCKET):$(CI_SOCKET)" -e DOCKER_HOST="$(CI_DAEMON_SOCKET)" \
	  --entrypoint /bin/bash $(CI_IMAGE) -lc \
	  'make ci-local-run RUNNER=$(RUNNER) CI_WORKFLOW=$(CI_WORKFLOW) \
	     CI_JOB=$(CI_JOB) CI_SOCKET=$(CI_SOCKET)'
