FROM full32:latest
RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y vim
RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y gdb
RUN env DEBIAN_FRONTEND=noninteractive apt-get install -y sudo
RUN useradd -d /home/peadar -u 11992 peadar -G sudo
RUN echo '%sudo ALL=(ALL)NOPASSWD:ALL' >> /etc/sudoers
WORKDIR /home/peadar
CMD sudo -iu peadar
