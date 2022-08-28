TARGET := iphone:clang:15.5:11.0
ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TOOL_NAME = opainject

opainject_FILES = main.m dyld.m shellcode_inject.m rop_inject.m
opainject_CFLAGS = -fobjc-arc -DTHEOS_LEAN_AND_MEAN
opainject_CODESIGN_FLAGS = -Sentitlements.plist
opainject_INSTALL_PATH = /usr/local/bin

include $(THEOS_MAKE_PATH)/tool.mk
