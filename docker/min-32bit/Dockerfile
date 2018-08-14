FROM i386/debian:stretch
RUN env DEBIAN_FRONTEND=noninteractive apt-get update
RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y cmake
RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y g++
WORKDIR /src/docker/min-32bit
CMD mkdir -p release && cd release && cmake -DCMAKE_BUILD_TYPE=Release ../../.. && make -j && cd .. && mkdir -p debug && cd debug && cmake -DCMAKE_BUILD_TYPE=Debug ../../.. && make -j
