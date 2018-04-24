#!/bin/bash

adb shell mount -o rw,remount /dev/block/mtdblock0 /system

adb shell rm /system/$1

adb push ./$1 /system/$1

adb shell insmod /system/$1

adb shell dmesg -c
