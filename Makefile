PREFIX ?= /usr/local
CC = $(CROSS_COMPILE)gcc
CFLAGS ?= -O2

NDK ?= /opt/android-ndk

SRCS = $(wildcard src/*.c)
HDRS = $(wildcard src/*.h)

OBJS = $(SRCS:%.c=%.o)
LIBS = -lpthread

.PHONY: clean all install

ifneq ($(DESTDIR),)
    INSTALLDIR = $(subst //,/,$(DESTDIR)/$(PREFIX))
else
    INSTALLDIR = $(PREFIX)
endif


all: wificurse

wificurse: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

install: all
	@mkdir -p $(INSTALLDIR)/bin
	cp wificurse $(INSTALLDIR)/bin/wificurse

.PHONY: android android-clean

android:
	$(NDK)/ndk-build -j$(shell nproc) NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=jni/Android.mk NDK_APPLICATION_MK=jni/Application.mk

android-clean:
	$(NDK)/ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=jni/Android.mk NDK_APPLICATION_MK=jni/Application.mk clean

clean:
	@rm -f src/*~ src/\#*\# src/*.o *~ \#*\# wificurse
