include config-plugin.mak
include $(SRC_PATH)/$(TARGET_DIR)/$(TARGET_CONFIG_MAKE)

DEFINES=-I. -I$(PLUGIN_PATH)/libart/ -I$(PLUGIN_PATH)/core/include -I$(PLUGIN_PATH)/valgrind/main -I$(PLUGIN_PATH)/valgrind/main/include -I$(PLUGIN_PATH)/gtest/include -I$(PLUGIN_PATH)/libnativehelper/include/nativehelper -I$(SRC_PATH) -I$(SRC_PATH)/qapi-auto-generated -I$(SRC_PATH)/include -I$(SRC_PATH)/plugins -I$(SRC_PATH)/fpu -I$(SRC_PATH)/DECAF_shared -I$(SRC_PATH)/DECAF_shared/DroidScope -I$(SRC_PATH)/target-$(TARGET_ARCH) -I$(SRC_PATH)/$(TARGET_DIR) -I$(SRC_PATH)/slirp
DEFINES+=-I. -I$(PLUGIN_PATH)/../../../libcxx/include
DEFINES+=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_GNU_SOURCE -DNEED_CPU_H -D_USING_LIBCXX
DEFINES+=$(GLIB_CFLAGS)
DEFINES+=$(TARGET_CFLAGS)
ART_SHLIB_32=$(SRC_PATH)/../../out/host/linux-x86/lib/libart.so
ART_SHLIB_64=$(SRC_PATH)/../../out/host/linux-x86/lib64/libart.so
CPP_SHLIB_64=$(SRC_PATH)/../../out/host/linux-x86/lib64/libc++.so

CC=clang-3.7
CPP=clang++-3.7
CFLAGS=-O2 -g -fPIC  -m64 `pkg-config --cflags glib-2.0` -fpermissive

CXXFLAGS=-O2 -g -fPIC  -m64 `pkg-config --cflags glib-2.0` -fpermissive -nostdinc++ -std=c++11
LDFLAGS=-g -shared -m64 `pkg-config --libs glib-2.0` -Wl,-rpath=$(PWD)/../../../../out/host/linux-x86/lib64/ -std=c++11 -Wno-c++11-extensions -nodefaultlibs

# capstone library name (without prefix 'lib' and suffix '.so')
LIBS+= -L./../../../../out/host/linux-x86/lib64/ $(ART_SHLIB_64) $(CPP_SHLIB_64) -lart -lm -lc

OBJS=unpacker.o
# temu, qemu-tools removed as target
all: libartt libunpacker.so

qemu-tools:
	make -C $(SRC_PATH) all

decaf:
	make -C $(TARGET_DIR) all


libartt: $(ART_SHLIB_64)

libunpacker.so: $(SHARED_LIBS) $(OBJS)
	$(CPP) $(LDFLAGS) $^ -o $@ $(LIBS)

libunpacker-static.so: $(OBJS)
	$(CPP) -static-libgcc -Wl,-static $(LDFLAGS) $^ -o $@ $(LIBS)

clean:
	rm -f *.d *.so *.a *~ $(PLUGIN)

realclean:
	rm -f *.d *.so *.a *~ $(PLUGIN) config-plugin.h config-plugin.mak

# Include automatically generated dependency files
-include $(wildcard *.d)

