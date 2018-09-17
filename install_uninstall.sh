#!/bin/bash

apk=$1
install=$2


if [ "$install" = "1" ] 
then
	#echo installing $filename
	adb shell setprop dalvik.vm.dex2oat-filter "interpret-only"
	adb shell setprop dalvik.vm.image-dex2oat-filter "interpret-only"
	adb install $apk
elif [ "$install" = "2" ]
then
	#echo uninstalling $filename
	packageName=$(/home/yduan/yueduan/android-5.0.0_r3/out/host/linux-x86/bin/aapt dump badging $apk | awk -v FS="'" '/package: name=/{print $2}')
	adb shell pm uninstall -k $packageName
fi
