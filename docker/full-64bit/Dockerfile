FROM debian:stretch
RUN env DEBIAN_FRONTEND=noninteractive apt-get update
RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y cmake
RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y g++
RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y zlib1g-dev
RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y liblzma-dev
RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y python-dev
RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y git-core
WORKDIR /src/docker/full-64bit
CMD mkdir -p release && cd release && cmake -DCMAKE_BUILD_TYPE=Release ../../.. && make -j && cd .. && mkdir -p debug && cd debug && cmake -DCMAKE_BUILD_TYPE=Debug ../../.. && make -j
