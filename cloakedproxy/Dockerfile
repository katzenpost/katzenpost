FROM docker.io/golang:bullseye AS builder

LABEL authors="Masala: masala@riseup.net"

# Install build requirements
RUN echo 'deb https://deb.debian.org/debian bullseye main\ndeb https://deb.debian.org/debian bullseye-updates main\ndeb https://deb.debian.org/debian-security bullseye-security main' > /etc/apt/sources.list && cat /etc/apt/sources.list
RUN apt update \
&& apt install --no-install-recommends -y git make ca-certificates \
build-essential libgles2 libgles2-mesa-dev libglib2.0-dev \
libxkbcommon-dev libxkbcommon-x11-dev libglu1-mesa-dev libxcursor-dev \
libwayland-dev libx11-xcb-dev libvulkan-dev \
&& update-ca-certificates
