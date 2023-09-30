warped?=false
KEYSTORE := sign.keystore
KEYPASS := password
CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f"
ldflags="-X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"
uid=$(shell [ "$$SUDO_UID" != "" ] && echo "$$SUDO_UID" || id -u)
gid=$(shell [ "$$SUDO_GID" != "" ] && echo "$$SUDO_GID" || id -g)
docker_user?=$(shell if echo ${docker}|grep -q podman; then echo 0:0; else echo ${uid}:${gid}; fi)
docker=$(shell if which podman|grep -q .; then echo podman; else echo docker; fi)
docker_args=--user ${docker_user} -v $(shell readlink -f ..):/go/katzenpost -e GOCACHE=/tmp/gocache -e CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f" -v $(shell pwd)/go_package_cache:/go/pkg --workdir /go/katzenpost --network=host --rm
distro?=alpine

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

docker-build-linux: docker-$(distro)-base
	$(docker) run $(docker_args)  katzen/$(distro)_base bash -c 'cd cloakedproxy; go build -trimpath -ldflags=${ldflags}'

docker-build-windows: docker-debian-base
	$(docker) run $(docker_args) katzen/$(distro)_base bash -c 'cd cloakedproxy; GOOS=windows CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc go build -trimpath -ldflags="-H windowsgui ${ldflags}" -o cloakedproxy.exe'

docker-android-shell: docker-android-base
	$(docker) run $(docker_args) --rm -it katzen/android_sdk bash

docker-clean:
	rm -rv go_package_cache
	$(docker) rm  katzen_debian_base || true
	$(docker) rmi katzen/$(distro)_base katzen/android_sdk || true

# this builds the debian base image, ready to have the golang deps installed
docker-debian-base: go_package_cache
	if ! $(docker) images|grep katzen/debian_base; then \
		$(docker) run --name katzen_debian_base docker.io/golang:bullseye bash -c "echo -e 'deb https://deb.debian.org/debian bullseye main\ndeb https://deb.debian.org/debian bullseye-updates main\ndeb https://deb.debian.org/debian-security bullseye-security main' > /etc/apt/sources.list && cat /etc/apt/sources.list && apt update && apt upgrade -y && apt install -y --no-install-recommends build-essential libgles2 libgles2-mesa-dev libglib2.0-dev libxkbcommon-dev libxkbcommon-x11-dev libglu1-mesa-dev libxcursor-dev libwayland-dev libx11-xcb-dev libvulkan-dev gcc-mingw-w64-x86-64" \
		&& $(docker) commit katzen_debian_base katzen/debian_base \
		&& $(docker) rm katzen_debian_base; \
	fi

docker-alpine-base: go_package_cache
	if ! $(docker) images|grep katzen/alpine_base; then \
		$(docker) run --name katzen_alpine_base docker.io/golang:alpine \
		sh -c 'apk add bash gcc musl-dev libxkbcommon-dev pkgconf wayland-dev \
					   vulkan-headers mesa-dev libx11-dev libxcursor-dev' \
		&& $(docker) commit katzen_alpine_base katzen/alpine_base \
		&& $(docker) rm katzen_alpine_base; \
	fi

docker-shell: docker-debian-base
	$(docker) $(docker_run_cmd) --rm -it katzen/$(distro)_base bash
