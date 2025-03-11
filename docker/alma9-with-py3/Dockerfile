FROM almalinux:9
RUN dnf install --enablerepo "baseos-debuginfo" -y epel-release
RUN dnf install --enablerepo "baseos-debuginfo" -y gcc
RUN dnf install --enablerepo "baseos-debuginfo" -y g++
RUN dnf install --enablerepo "baseos-debuginfo" -y cmake
RUN dnf install --enablerepo "baseos-debuginfo" -y zlib-devel
RUN dnf install --enablerepo "baseos-debuginfo" -y xz-devel
RUN dnf install --enablerepo "baseos-debuginfo" -y python3-devel
RUN dnf install --enablerepo "baseos-debuginfo" -y python3-debuginfo
RUN dnf install --enablerepo "baseos-debuginfo" -y elfutils-debuginfod-client-devel
WORKDIR /src/docker/alma9-with-py3
CMD ls -lsa /usr/bin/cmake && mkdir -p release && cd release && cmake -DPYTHON3=ON -DPYTHON3_SOURCE="/usr/include/python3.9" -DCMAKE_BUILD_TYPE=Release ../../.. && make -j && cd .. && mkdir -p debug && cd debug && cmake -DPYTHON3=ON -DPYTHON3_SOURCE="/usr/include/python3.9" -DCMAKE_BUILD_TYPE=Debug ../../.. && make -j && make test
