#
# Copyright (C) 2011 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_PATH := $(call my-dir)

include art/build/Android.executable.mk

OATDUMP_SRC_FILES := \
  myoatdump.cc

ifeq ($(ART_BUILD_HOST_NDEBUG),true)
  $(eval $(call build-art-shlib,oatdump,$(OATDUMP_SRC_FILES),libart-disassembler,art/disassembler,host,ndebug))
endif
ifeq ($(ART_BUILD_HOST_DEBUG),true)
  $(eval $(call build-art-shlib,oatdump,$(OATDUMP_SRC_FILES),libartd-disassembler,art/disassembler,host,debug))
endif

.PHONY: build-art-host-ok
build-art-host-ok:   $(ART_HOST_EXECUTABLES)   $(ART_HOST_GTEST_EXECUTABLES)   $(HOST_CORE_IMG_OUT)   $(ART_HOST_OUT_SHARED_LIBRARIES)/libjavacore$(ART_HOST_SHLIB_EXTENSION) $(HOST_OUT)/lib/libart-dscopeartdump.so $(HOST_OUT)/lib64/libart-dscopeartdump.so
