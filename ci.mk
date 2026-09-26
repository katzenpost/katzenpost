# SPDX-License-Identifier: AGPL-3.0-only

ci_container?=podman
ci_runner_image?=docker.io/catthehacker/ubuntu:act-22.04
ci_platform?=ubuntu-latest=$(ci_runner_image)
ci_act?=act
ci_forgejo_runner?=forgejo-runner
ci_workflow_github?=.github/workflows/linux.yml
ci_workflow_forgejo?=.forgejo/workflows/ci.yml
ci_job?=
ci_container_socket?=/run/user/$(shell id -u)/podman/podman.sock
ci_container_options?=-v /etc/ssl/certs:/etc/ssl/certs:ro -v $(ci_container_socket):/var/run/docker.sock
ci_act_flags?=--bind
ci_forgejo_flags?=--bind
ci_unit_cmd?=
ci_integration_cmd?=
ci_live_cmd?=

.PHONY: ci-unit ci-integration ci-live ci-image ci-act ci-forgejo ci-equivalence ci-clean

ci-unit:
	@test -n "$(ci_unit_cmd)" || { echo "set ci_unit_cmd before including ci.mk" >&2; exit 1; }
	$(ci_unit_cmd)

ci-integration:
	@test -n "$(ci_integration_cmd)" || { echo "set ci_integration_cmd before including ci.mk" >&2; exit 1; }
	$(ci_integration_cmd)

ci-live:
	@test -n "$(ci_live_cmd)" || { echo "set ci_live_cmd before including ci.mk" >&2; exit 1; }
	$(ci_live_cmd)

ci-image:
	$(ci_container) pull $(ci_runner_image)

ci-act: ci-image
	$(ci_act) $(ci_act_flags) -P $(ci_platform) --container-options "$(ci_container_options)" -W $(ci_workflow_github) $(if $(ci_job),-j $(ci_job),)

ci-forgejo: ci-image
	$(ci_forgejo_runner) exec $(ci_forgejo_flags) -P $(ci_platform) --container-options "$(ci_container_options)" -W $(ci_workflow_forgejo) $(if $(ci_job),-j $(ci_job),)

ci-equivalence:
	@a=0; b=0; \
	$(MAKE) ci-act > ci-act.log 2>&1 || a=$$?; \
	$(MAKE) ci-forgejo > ci-forgejo.log 2>&1 || b=$$?; \
	echo "act=$$a forgejo=$$b"; \
	test "$$a" = "$$b" || { echo "the runners disagree; see ci-act.log and ci-forgejo.log" >&2; exit 1; }

ci-clean:
	rm -f ci-act.log ci-forgejo.log
