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

# Optional: write 'KH\n' to PL011 UART at start of setup_entry.
# Only enable for path-2 hang diagnosis (KH_UART_DEBUG=1 make).
ifeq ($(KH_UART_DEBUG),1)
ASFLAGS += -DKH_UART_DEBUG
endif

# Optional: enable MAP_DEBUG for paging_init runtime tracing.
ifeq ($(KH_MAP_DEBUG),1)
CFLAGS += -DMAP_DEBUG
ASFLAGS += -DMAP_DEBUG
endif

# Optional: cut asm _paging_init after mem_proc + paging_init + ret.
# Bisects which post-mem_proc step causes hang.
ifeq ($(KH_ASM_MID_CUT),1)
ASFLAGS += -DKH_ASM_MID_CUT
endif
ifeq ($(KH_ASM_MID2_CUT),1)
ASFLAGS += -DKH_ASM_MID2_CUT
endif
ifeq ($(KH_ASM_MID3_CUT),1)
ASFLAGS += -DKH_ASM_MID3_CUT
endif
ifeq ($(KH_ASM_MID4_CUT),1)
ASFLAGS += -DKH_ASM_MID4_CUT
endif
ifeq ($(KH_ASM_MID4A_CUT),1)
ASFLAGS += -DKH_ASM_MID4A_CUT
endif
ifeq ($(KH_ASM_MID4B_CUT),1)
ASFLAGS += -DKH_ASM_MID4B_CUT
endif
ifeq ($(KH_ASM_MID4C_CUT),1)
ASFLAGS += -DKH_ASM_MID4C_CUT
endif
INCLUDE := -Iinclude -Isrc -I$(KH_ROOT)/include

SRCS_C := src/setup.c src/start.c src/kh_load.c src/kh_lkm_load.c \
          src/tlsf.c src/baselib.c src/sha256.c src/map.c
SRCS_S := src/setup1.S src/cache.S src/map1.S src/kh_lkm_hook.S src/paging_init.S
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
