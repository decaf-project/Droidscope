# README
A docker file to build droidscope environment
## Steps to run droidscope in docker:
### 1.Build the docker image
`docker build --network=host -t droidscope /path/to/the/dockerfile`
### 2.search the created image:
`sudo docker image ls`
and copy that IMAGE ID
### 3.start the docker image:
`sudo docker run -it -e DISPLAY -v /PATH/TO/ANDROID/SOURCE/:/home/developer/android_source -v /tmp/.X11-unix:/tmp/.X11-unix -v $HOME/.Xauthority:/home/developer/.Xauthority --net=host IMAGE_ID`
### 4.start droidscope in docker container:
`./startDroidScope.sh`
