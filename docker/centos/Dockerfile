FROM centos:centos7
WORKDIR /src/docker/full-64bit
CMD mkdir -p release && cd release && cmake -DCMAKE_BUILD_TYPE=Release ../../.. && make -j && cd .. && mkdir -p debug && cd debug && cmake -DCMAKE_BUILD_TYPE=Debug ../../.. && make -j && make test
