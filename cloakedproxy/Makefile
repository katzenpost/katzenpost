warped?=false
KEYSTORE := sign.keystore
KEYPASS := password
CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f"
ldflags="-X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"
uid=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)
docker_user?=$(shell if echo ${docker}|grep -q podman; then echo 0:0; else echo ${uid}:${gid}; fi)
docker=$(shell if which podman|grep -q .; then echo podman; else echo docker; fi)
docker_args=--user ${docker_user} -v $(shell readlink -f ..):/go/katzenpost -e GOCACHE=/tmp/gocache -e CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f" --workdir /go/katzenpost --network=host --rm

all:
	CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go build -ldflags ${ldflags} .

go_package_cache:
	mkdir -p go_package_cache

docker-android-base:
	if ! $(docker) images|grep katzen/android_sdk; then \
		$(docker) build -t katzen/android_sdk -f Dockerfile.android .; \
	fi

$(KEYSTORE):
	$(docker) run $(docker_args) katzen/android_sdk bash -c "cd cloakedproxy && keytool -genkey -keystore $(KEYSTORE) -storepass ${KEYPASS} -alias android -keyalg RSA -keysize 2048 -validity 10000 -noprompt -dname CN=android"

docker-build-android: go_package_cache docker-android-base $(KEYSTORE)
	$(docker) run $(docker_args) katzen/android_sdk bash -c "go install gioui.org/cmd/gogio && cd cloakedproxy && gogio -arch arm64,amd64 -x -target android -appid proxy.cloaked -version 1 -signkey $(KEYSTORE) -signpass ${KEYPASS} ."

docker-android-shell: docker-android-base
	$(docker) run $(docker_args) -it katzen/android_sdk bash
