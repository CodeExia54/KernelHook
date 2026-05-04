# SPDX-License-Identifier: GPL-2.0-or-later
# Build khimg — KernelHook freestanding boot blob.

TARGET := khimg

# Cross-compiler: NDK clang for aarch64-linux-android.
KH_ROOT := $(shell cd .. && pwd)
include $(KH_ROOT)/kmod/mk/detect_toolchain.mk

CC := $(KH_CC)
LD := $(KH_LD)

_OBJCOPY_TRY := $(shell command -v $(KH_CROSS_COMPILE)objcopy 2>/dev/null)
ifeq ($(_OBJCOPY_TRY),)
    OBJCOPY := llvm-objcopy
else
    OBJCOPY := $(KH_CROSS_COMPILE)objcopy
endif

CFLAGS := -Wall -Wno-unused-function -fno-builtin -std=gnu11 \
          -nostdinc -mgeneral-regs-only \
          -ffreestanding -fno-stack-protector -fno-PIE -fno-pic \
          -fno-common -O2 -target aarch64-linux-gnu
ASFLAGS := -Wall -fno-builtin -std=gnu11 \
           -nostdinc -mgeneral-regs-only \
           -ffreestanding -fno-stack-protector -fno-PIE -fno-pic \
           -fno-common -O2 -target aarch64-linux-gnu
INCLUDE := -Iinclude -Isrc -I$(KH_ROOT)/include

SRCS_C := src/setup.c src/start.c src/kh_load.c src/kh_lkm_load.c \
          src/tlsf.c src/baselib.c src/sha256.c src/map.c
SRCS_S := src/setup1.S src/cache.S src/map1.S src/kh_lkm_hook.S
OBJS_C := $(SRCS_C:.c=.o)
OBJS_S := $(SRCS_S:.S=.o)
OBJS   := $(OBJS_C) $(OBJS_S)

all: $(TARGET)

$(TARGET): $(TARGET).elf
	$(OBJCOPY) -O binary -S $< $@
	@printf "[khimg] binary: %d bytes\n" "$$(wc -c < $@)"

$(TARGET).elf: $(OBJS)
	$(LD) -nostdlib -static -no-pie -T khimg.lds -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $@ $<

%.o: %.S
	$(CC) $(ASFLAGS) $(INCLUDE) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET).elf $(TARGET)

.PHONY: all clean
