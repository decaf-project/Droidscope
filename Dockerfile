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
RUN apt-get install vim -y
RUN apt-get install git-core gnupg flex bison gperf build-essential -y
RUN apt-get install tar wget zlib1g-dev libc6-dev-i386 -y
RUN apt-get install lib32ncurses5-dev x11proto-core-dev libx11-dev lib32z-dev ccache -y
RUN apt-get install libgl1-mesa-dev libxml2-utils xsltproc unzip m4 -y
RUN apt-get install gcc-4.8 gcc-4.8-multilib g++-4.8 g++-4.8-multilib -y
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.8 50

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
RUN mkdir -p /home/developer/android_source
RUN mkdir -p /home/developer/android_source/external
RUN mkdir -p /home/developer/android_source/prebuilts
RUN mkdir -p /home/developer/android_source/out
RUN mkdir -p /home/developer/images
RUN mkdir -p /home/developer/droidscope

WORKDIR /home/developer/
#RUN sudo git clone https://github.com/bitsecurerlab/Droidscope.git

