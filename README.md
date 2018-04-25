# README
A docker file to build droidscope environment
## Build the docker image
`docker build --network=host -t droidscope /path/to/the/dockerfile`
## how to use droidscope?
### 1.search the created image:
`sudo docker image ls`
and copy that IMAGE ID
### 2.start the docker image:
`sudo docker run -it -e DISPLAY -v /PATH/TO/ANDROID/SOURCE/:/home/developer/android_source -v /tmp/.X11-unix:/tmp/.X11-unix -v $HOME/.Xauthority:/home/developer/.Xauthority --net=host IMAGE_ID`
### 3.start droidscope in docker container:
`./startDroidScope.sh`
