include config-plugin.mak
include $(SRC_PATH)/$(TARGET_DIR)/$(TARGET_CONFIG_MAKE)

DEFINES=-I. -I$(SRC_PATH) -I$(SRC_PATH)/qapi-auto-generated -I$(SRC_PATH)/include -I$(SRC_PATH)/plugins -I$(SRC_PATH)/fpu -I$(SRC_PATH)/DECAF_shared -I$(SRC_PATH)/DECAF_shared/DroidScope -I$(SRC_PATH)/target-$(TARGET_ARCH) -I$(SRC_PATH)/$(TARGET_DIR) -I$(SRC_PATH)/slirp
DEFINES+=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_GNU_SOURCE -DNEED_CPU_H
DEFINES+=$(GLIB_CFLAGS)
DEFINES+=$(TARGET_CFLAGS)

CC=gcc
CPP=g++
CFLAGS=-Wall -O2 -g -fPIC  -m64 `pkg-config --cflags glib-2.0` -fpermissive
# CFLAGS=-Wall -g -fPIC

CXXFLAGS=-Wall -O2 -g -fPIC  -m64 `pkg-config --cflags glib-2.0` -fpermissive -std=gnu++11
LDFLAGS=-g -shared -m64 -Wl,-rpath=$(PWD)/capstone-master/ `pkg-config --libs glib-2.0`

# capstone library name (without prefix 'lib' and suffix '.so')
#LIBS+=-L./capstone-master/ -lcapstone

OBJS=javatracer.o
# temu, qemu-tools removed as target
all: libjavatracer.so

qemu-tools:
	make -C $(SRC_PATH) all

decaf:
	make -C $(TARGET_DIR) all

%.o: %.c
	$(CC) $(CFLAGS) $(DEFINES) -c -o $@ $<

%.o: %.cpp
	$(CPP) $(CXXFLAGS) $(DEFINES) -c -o $@ $<

libjavatracer.so: $(SHARED_LIBS) $(OBJS)
	$(CPP) $(LDFLAGS) $^ -o $@ $(LIBS)

libjavatracer-static.so: $(OBJS)
	$(CPP) -static-libgcc -Wl,-static $(LDFLAGS) $^ -o $@ $(LIBS)

clean:
	rm -f *.o *.d *.so *.a *~ $(PLUGIN)

realclean:
	rm -f *.o *.d *.so *.a *~ $(PLUGIN) config-plugin.h config-plugin.mak

# Include automatically generated dependency files
-include $(wildcard *.d)

