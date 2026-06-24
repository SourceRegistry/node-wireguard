FROM node:24-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libmnl-dev \
        libssl-dev \
        wireguard-tools \
        iproute2 \
        git \
    && rm -rf /var/lib/apt/lists/*
