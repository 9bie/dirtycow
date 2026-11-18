/*
 * C replacement for the old file_strip.py (which needed python3 + pyelftools).
 *
 * Extracts the bytes between the __shellcode_start and __shellcode_end
 * symbols of the standalone ELF64 binary built from backdoor/ and writes
 * them as a C array (unsigned char shellcode[] + unsigned int shellcode_size).
 *
 * The symbol values are used directly as file offsets, exactly like the
 * original script did: the linker script maps the payload so that its
 * virtual addresses and file offsets coincide.
 *
 * Usage: file_strip <input-elf> <output.c>
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHT_SYMTAB 2

typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf64_ehdr;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} elf64_shdr;

typedef struct {
    uint32_t st_name;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} elf64_sym;

static void die(const char *msg) {
    fprintf(stderr, "file_strip: %s\n", msg);
    exit(1);
}

static unsigned char *load_file(const char *path, size_t *size) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror(path);
        exit(1);
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        perror(path);
        exit(1);
    }
    long end = ftell(fp);
    if (end < 0) {
        perror(path);
        exit(1);
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        perror(path);
        exit(1);
    }
    size_t len = (size_t) end;
    unsigned char *data = malloc(len ? len : 1);
    if (!data) {
        die("out of memory");
    }
    if (len && fread(data, 1, len, fp) != len) {
        die("short read");
    }
    fclose(fp);
    *size = len;
    return data;
}

static const elf64_shdr *get_shdr(const unsigned char *buf, const elf64_ehdr *eh, unsigned int index) {
    return (const elf64_shdr *) (buf + eh->e_shoff + (uint64_t) index * eh->e_shentsize);
}

static uint64_t find_symbol(const unsigned char *buf, size_t size, const elf64_ehdr *eh,
                            const elf64_shdr *symtab, const char *name) {
    if (symtab->sh_offset > size || symtab->sh_size > size - symtab->sh_offset) {
        die("symbol table out of bounds");
    }
    if (symtab->sh_link >= eh->e_shnum) {
        die("bad symbol table string table link");
    }
    const elf64_shdr *strtab = get_shdr(buf, eh, symtab->sh_link);
    if (strtab->sh_offset > size || strtab->sh_size > size - strtab->sh_offset) {
        die("string table out of bounds");
    }

    size_t count = (size_t) (symtab->sh_size / sizeof(elf64_sym));
    for (size_t i = 0; i < count; i++) {
        const elf64_sym *sym = (const elf64_sym *) (buf + symtab->sh_offset + i * sizeof(elf64_sym));
        if (sym->st_name >= strtab->sh_size) {
            continue;
        }
        const char *sym_name = (const char *) (buf + strtab->sh_offset + sym->st_name);
        size_t max_len = (size_t) (strtab->sh_size - sym->st_name);
        if (strnlen(sym_name, max_len) == max_len) {
            continue;
        }
        if (strcmp(sym_name, name) == 0) {
            return sym->st_value;
        }
    }
    fprintf(stderr, "file_strip: symbol %s not found\n", name);
    exit(1);
}

static void emit_c_array(FILE *out, const unsigned char *data, size_t len) {
    fputs("unsigned char shellcode[] = {\n", out);
    for (size_t i = 0; i < len; i += 16) {
        size_t n = len - i < 16 ? len - i : 16;
        for (size_t j = 0; j < n; j++) {
            fprintf(out, "%s0x%02x", j ? ", " : "", data[i + j]);
        }
        fputs(",\n", out);
    }
    fputs("};\n", out);
    fprintf(out, "unsigned int shellcode_size = %u;\n", (unsigned int) len);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <input-elf> <output.c>\n", argv[0]);
        return 1;
    }

    size_t size;
    unsigned char *buf = load_file(argv[1], &size);

    if (size < sizeof(elf64_ehdr)) {
        die("file is too small to be an ELF64 file");
    }
    const elf64_ehdr *eh = (const elf64_ehdr *) buf;
    if (memcmp(eh->e_ident, "\177ELF", 4) != 0) {
        die("not an ELF file");
    }
    if (eh->e_ident[4] != 2) {
        die("not a 64-bit ELF file");
    }
    if (eh->e_ident[5] != 1) {
        die("expecting a little-endian ELF file");
    }
    if (eh->e_shentsize != sizeof(elf64_shdr)) {
        die("unexpected section header size");
    }
    if (eh->e_shoff > size || (uint64_t) eh->e_shnum * eh->e_shentsize > size - eh->e_shoff) {
        die("section headers out of bounds");
    }

    const elf64_shdr *symtab = NULL;
    for (unsigned int i = 0; i < eh->e_shnum; i++) {
        const elf64_shdr *sh = get_shdr(buf, eh, i);
        if (sh->sh_type == SHT_SYMTAB) {
            symtab = sh;
            break;
        }
    }
    if (!symtab) {
        die("no symbol table (.symtab) found");
    }

    uint64_t start = find_symbol(buf, size, eh, symtab, "__shellcode_start");
    uint64_t end = find_symbol(buf, size, eh, symtab, "__shellcode_end");
    if (end < start) {
        die("__shellcode_end is before __shellcode_start");
    }

    /* Same truncation behavior as the python script: never read past EOF. */
    size_t len = 0;
    if (start < size) {
        uint64_t available = size - start;
        uint64_t wanted = end - start;
        len = (size_t) (wanted < available ? wanted : available);
    }

    FILE *out = fopen(argv[2], "w");
    if (!out) {
        perror(argv[2]);
        return 1;
    }
    emit_c_array(out, buf + start, len);
    if (fclose(out) != 0) {
        perror(argv[2]);
        return 1;
    }

    free(buf);
    return 0;
}
