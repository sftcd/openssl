#!/bin/bash

# set environment for android build

# You'll need to fix the ANDROID_NDK to match where you put stuff
export ANDROID_NDK=$HOME/code/android/NDK/android-ndk-r16b
export PATH=$ANDROID_NDK/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$PATH

# configure command for openssl 
# ./Configure android-arm -D__ANDROID_API__=16
