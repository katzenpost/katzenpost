warped?=false
ldflags="-X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"

run-nonvoting-testnet: server nonvoting_authority
	./fix_perms.sh; cd nonvoting_mixnet; docker-compose up

run-voting-testnet: server voting_authority
	./fix_perms.sh; cd voting_mixnet; docker-compose up

debian_base:
	if ! docker images|grep katzenpost/debian_base; then \
		docker run --name katzenpost_debian_base -it golang:buster bash -c 'apt update && apt upgrade -y' \
		&& docker commit katzenpost_debian_base katzenpost/debian_base \
		&& docker rm katzenpost_debian_base; \
	fi

deps: debian_base
	if ! docker images|grep katzenpost/deps; then \
		docker run -v $(shell readlink -f ..):/go/katzenpost --name katzenpost_deps -it katzenpost/debian_base \
			bash -c 'cd /go/katzenpost; go mod download' \
		&& docker commit katzenpost_deps katzenpost/deps \
		&& docker rm katzenpost_deps; \
	fi

update-deps: deps
	docker run -v $(shell readlink -f ..):/go/katzenpost --name katzenpost_deps -it katzenpost/deps \
			bash -c 'cd /go/katzenpost; go mod tidy; go mod download' \
		&& docker commit katzenpost_deps katzenpost/deps \
		&& docker rm katzenpost_deps

server: deps
	if ! docker images|grep katzenpost/server; then \
		docker run -v $(shell readlink -f ..):/go/katzenpost --name katzenpost_server -it katzenpost/deps \
			bash -c 'cd /go/katzenpost/server; make testnet-build; make testnet-install' \
		&& docker commit katzenpost_server katzenpost/server \
		&& docker rm katzenpost_server; \
	fi

voting_authority: deps
	if ! docker images|grep katzenpost/voting_authority; then \
		docker run -v $(shell readlink -f ..):/go/katzenpost --name katzenpost_voting_authority -it katzenpost/deps \
			bash -c 'cd /go/katzenpost/authority/cmd/voting && go install -ldflags ${ldflags}' \
		&& docker commit katzenpost_voting_authority katzenpost/voting_authority \
		&& docker rm katzenpost_voting_authority; \
	fi

nonvoting_authority: deps
	if ! docker images|grep katzenpost/nonvoting_authority; then \
		docker run -v $(shell readlink -f ..):/go/katzenpost --name katzenpost_nonvoting_authority -it katzenpost/deps \
			bash -c 'cd /go/katzenpost/authority/cmd/nonvoting && go install -ldflags ${ldflags}' \
		&& docker commit katzenpost_nonvoting_authority katzenpost/nonvoting_authority \
		&& docker rm katzenpost_nonvoting_authority; \
	fi

clean-local-images:
	cd nonvoting_mixnet; docker-compose rm -sf
	cd voting_mixnet; docker-compose rm -sf
	docker rm  katzenpost_server katzenpost_voting_authority katzenpost_nonvoting_authority || true
	docker rmi katzenpost/server katzenpost/voting_authority katzenpost/nonvoting_authority || true

clean-images: clean-local-images
	docker rm  katzenpost_debian_base katzenpost_deps || true
	docker rmi katzenpost/debian_base katzenpost/deps || true

clean-data-dryrun:
	git clean -n nonvoting_mixnet voting_mixnet

clean-data:
	git clean -f nonvoting_mixnet voting_mixnet

clean-local: clean-local-images clean-data

clean: clean-images clean-data

