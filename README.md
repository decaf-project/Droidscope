# README
A docker file to build droidscope environment  
## Host environment:  
* android-5.0.0_r2  
* goldfish3.4  
* docker  
* Please find more instructions here:  
* https://source.android.com/setup/build/downloading  
 https://github.com/enlighten5/android_build  

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
