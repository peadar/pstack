FROM i386/debian:stretch
RUN env DEBIAN_FRONTEND=noninteractive apt-get update
RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y cmake
RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y g++
RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y python
WORKDIR /src/docker/min-32bit
CMD mkdir -p release && cd release && cmake -DCMAKE_BUILD_TYPE=Release ../../.. && make -j && cd .. && mkdir -p debug && cd debug && cmake -DCMAKE_BUILD_TYPE=Debug ../../.. && make -j && make test
