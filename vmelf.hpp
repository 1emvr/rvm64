#ifndef VMELF_H
#define VMELF_H

#define EI_NIDENT 16
#define PT_LOAD 1
#define ET_EXEC 2
#define ET_DYN  3

#include <windows.h>
#include <cstdio>
#include <cstdint>

#include "vmmain.hpp"
typedef struct {
    uint8_t  e_ident[EI_NIDENT]; // ELF magic, class, data, etc.
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;    // Virtual address of entry point
    uint64_t e_phoff;    // Program header offset
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;    // Number of program headers
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} e_ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;   // Offset in file
    uint64_t p_vaddr;    // Virtual address in memory
    uint64_t p_paddr;
    uint64_t p_filesz;   // Bytes in file
    uint64_t p_memsz;    // Bytes in memory
    uint64_t p_align;
} e_phdr;

namespace rvm64::elf {
    bool load_elf64_image(void) {
        if (!vmcs->program.address || !vmcs->process.address) {
            return false;
        }

        e_ehdr* e_head = (e_ehdr*)vmcs->program.address;
        if (!(e_head->e_ident[0] == 0x7F &&
              e_head->e_ident[1] == 'E' &&
              e_head->e_ident[2] == 'L' &&
              e_head->e_ident[3] == 'F'))
        {
            return false;
        }

        if (e_head->e_type != ET_EXEC) {
            return false;
        }

        e_phdr* p_heads = (e_phdr*)(vmcs->program.address + e_head->e_phoff);
        uint64_t base_vaddr = UINT64_MAX;

        for (int i = 0; i < e_head->e_phnum; i++) {
            if (p_heads[i].p_type == PT_LOAD && p_heads[i].p_filesz > 0) {
                if (p_heads[i].p_vaddr < base_vaddr) {
                    base_vaddr = p_heads[i].p_vaddr;
                }
            }
        }

        if (base_vaddr == UINT64_MAX) {
            return false;
        }

        for (int i = 0; i < e_head->e_phnum; i++) {
            e_phdr* ph = &p_heads[i];

            if (ph->p_vaddr < base_vaddr) {
                return false;
            }

            uint64_t offset = ph->p_vaddr - base_vaddr;
            if (ph->p_type != PT_LOAD) {
                continue;
            }
            if (offset + ph->p_memsz > vmcs->process.size) {
                printf("Segment out of bounds: offset 0x%llx memsz 0x%llx > vmcs->process.address size 0x%zx - Consider increasing vram.\n", offset, ph->p_memsz, vmcs->process.size);
                return false;
            }

            void* src = (void*)vmcs->program.address + ph->p_offset;
            void* dst = (void*)vmcs->process.address + offset;

            memcpy(dst, src, ph->p_filesz);

            if (ph->p_memsz > ph->p_filesz) {
                memset((uint8_t*)dst + ph->p_filesz, 0, ph->p_memsz - ph->p_filesz);
            }
        }

        vmcs->pc = vmcs->process.address + (e_head->e_entry - base_vaddr);
        return true;
    }
};
#endif // VMELF_H
