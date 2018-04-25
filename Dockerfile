FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install libsdl1.2-dev -y
RUN apt-get install zlib1g-dev -y
RUN apt-get install libglib2.0-dev -y
RUN apt-get install libbfd-dev -y
RUN apt-get install build-essential -y
RUN apt-get install binutils -y
RUN apt-get install qemu -y
RUN apt-get install libboost-dev -y
RUN apt-get install git -y
RUN apt-get install libtool -y
RUN apt-get install autoconf -y
RUN apt-get install sudo -y
RUN apt-get install xorg-dev -y
RUN apt-get install git-core gnupg flex bison gperf build-essential -y
RUN apt-get install tar wget zlib1g-dev libc6-dev-i386 -y
RUN apt-get install lib32ncurses5-dev x11proto-core-dev libx11-dev lib32z-dev ccache -y
RUN apt-get install libgl1-mesa-dev libxml2-utils xsltproc unzip m4 -y


# Replace 1000 with your user / group id
RUN export uid=1000 gid=1000 && \
    mkdir -p /home/developer && \
    echo "developer:x:${uid}:${gid}:Developer,,,:/home/developer:/bin/bash" >> /etc/passwd && \
    echo "developer:x:${uid}:" >> /etc/group && \
    echo "developer ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/developer && \
    chmod 0440 /etc/sudoers.d/developer && \
    chown ${uid}:${gid} -R /home/developer

USER developer
ENV HOME /home/developer

WORKDIR /home/developer
RUN sudo git clone https://github.com/enlighten5/Droidscope.git
RUN wget https://s3-us-west-1.amazonaws.com/droidscope/image.tar.gz


WORKDIR /home/developer
RUN sudo tar -xvf /home/developer/image.tar.gz

WORKDIR /home/developer/Droidscope/droidscope
