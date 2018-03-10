FROM 32bit/debian:stretch
RUN env DEBIAN_FRONTEND=noninteractive apt-get update
RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y cmake
RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y g++
RUN mkdir -p /src
WORKDIR /src/docker/min-32bit/out
CMD cmake -DCMAKE_BUILD_TYPE=Release ../../.. && make -j
