# Build requires only make and gcc.
CC = gcc

# Static by default: the target machine does not need make, gcc,
# a dynamic loader or a matching glibc.  Use "make STATIC=0" for dynamic.
STATIC ?= 1
ifeq ($(STATIC),1)
STATIC_FLAGS := -static
else
STATIC_FLAGS :=
endif

BUILD_DIR   := build
TARGET      := dirtycow
SCMAKER     := $(BUILD_DIR)/ScMaker
FILE_STRIP  := $(BUILD_DIR)/file_strip
SHELLCODE_C := $(BUILD_DIR)/shellcode.c

MAIN_SRCS := dirtycow.c exploit.c unit.c vdso_backdoor.c
MAIN_HDRS := dirtycow.h exploit.h unit.h vdso_backdoor.h

BACKDOOR_SRCS := backdoor/backdoor.c \
	$(wildcard backdoor/libc/*.c) \
	$(wildcard backdoor/linux_syscalls/*.c)
BACKDOOR_HDRS := $(wildcard backdoor/libc/*.h) \
	$(wildcard backdoor/linux_syscalls/*.h)

# Same flags the CMake build used for the standalone backdoor binary.
SC_CFLAGS := -std=gnu99 -D_FORTIFY_SOURCE=0 -fshort-wchar -fno-builtin-printf \
	-fno-asynchronous-unwind-tables -ffreestanding -ffunction-sections \
	-fdata-sections -fPIC -fPIE -pie -Os \
	-Ibackdoor/libc -Ibackdoor/linux_syscalls

SC_LDFLAGS := -nostartfiles -nodefaultlibs -Wl,--gc-sections \
	-fPIC -fPIE -pie -Os -Tbackdoor/standalone_elf64.lds -lgcc

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Standalone ELF whose payload is delimited by __shellcode_start/__shellcode_end.
$(SCMAKER): $(BACKDOOR_SRCS) $(BACKDOOR_HDRS) backdoor/standalone_elf64.lds | $(BUILD_DIR)
	$(CC) $(SC_CFLAGS) -o $@ $(BACKDOOR_SRCS) $(SC_LDFLAGS)

# C replacement for script/file_strip.py (no python3, no pyelftools).
$(FILE_STRIP): script/file_strip.c | $(BUILD_DIR)
	$(CC) -O2 -std=gnu99 -o $@ $<

# Turn the payload inside ScMaker into a C array.
$(SHELLCODE_C): $(SCMAKER) $(FILE_STRIP) | $(BUILD_DIR)
	$(FILE_STRIP) $(SCMAKER) $@

$(TARGET): $(MAIN_SRCS) $(MAIN_HDRS) $(SHELLCODE_C)
	$(CC) -O2 -std=gnu99 -D_GNU_SOURCE -pthread $(STATIC_FLAGS) -o $@ $(MAIN_SRCS) $(SHELLCODE_C)

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

.DELETE_ON_ERROR:
.PHONY: all clean
