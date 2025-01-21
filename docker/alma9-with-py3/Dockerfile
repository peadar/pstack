FROM almalinux:9
RUN dnf install --enablerepo "baseos-debuginfo" -y epel-release cmake zlib-devel xz-devel python3-devel python3-debuginfo gcc g++
WORKDIR /src/docker/alma9-with-py3
CMD ls -lsa /usr/bin/cmake && mkdir -p release && cd release && cmake -DPYTHON3=ON -DPYTHON3_SOURCE="/usr/include/python3.9" -DCMAKE_BUILD_TYPE=Release ../../.. && make -j && cd .. && mkdir -p debug && cd debug && cmake -DCMAKE_BUILD_TYPE=Debug ../../.. && make -j && make test
