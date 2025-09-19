#ifndef VMELF_H
#define VMELF_H
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#include "../include/vmmain.hpp"
#include "../include/vmlib.hpp"

#include "rvni.hpp"

// Dynamic section tags
#define DT_NULL         0       
#define DT_PLTGOT		3		
#define DT_SYMTAB       6       
#define DT_STRTAB       5       
#define DT_STRSZ 		10
#define DT_SYMENT       11      
#define DT_JMPREL       23     
#define DT_PLTRELSZ     2     
#define DT_PLTREL       20   
#define DT_RELA         7   
#define DT_RELASZ       8  
#define DT_RELAENT      9 
								
#define EI_MAG0			0   
#define EI_MAG1			1   
#define EI_MAG2			2  
#define EI_MAG3			3 
#define EI_CLASS		4
#define EI_DATA			5  
#define EI_VERS			6 
#define EI_OSAB			7
#define EI_ABIVERSION	8 
#define EI_PAD			9   
#define EI_NIDENT		16 

#define ELFCLASS32		1
#define ELFCLASS64		2

#define ET_NONE			0 
#define ET_REL 			1 
#define ET_EXEC			2 
#define ET_DYN 			3 
#define ET_CORE			4 

#define EM_NONE			0
#define EM_RISC			243 

#define PT_NULL			0
#define PT_LOAD			1
#define PT_DYNA			2
#define PT_INTE			3
#define PT_NOTE			4
#define PT_SHLI			5
#define PT_PHDR			6
#define PT_TLS 			7

#define SHT_NULL        0           
#define SHT_PROGBITS    1           
#define SHT_SYMTAB      2           
#define SHT_STRTAB      3           
#define SHT_RELA        4           
#define SHT_NOBITS      8           
#define SHT_DYNSYM      11          
									
#define SHN_UNDEF 		0	
#define SHN_LORESERVE   0xff00
#define SHN_LOPROC      0xff00
#define SHN_HIPROC      0xff1f
#define SHN_ABS         0xfff1   
#define SHN_COMMON      0xfff2   
#define SHN_HIRESERVE   0xffff

#define R_RISCV_NONE          	0
#define R_RISCV_32             	1   
#define R_RISCV_64             	2   
#define R_RISCV_RELATIVE       	3   
#define R_RISCV_COPY           	4   
#define R_RISCV_JUMP_SLOT      	5   
#define R_RISCV_TLS_DTPMOD32   	6
#define R_RISCV_TLS_DTPMOD64   	7
#define R_RISCV_TLS_DTPREL32   	8
#define R_RISCV_TLS_DTPREL64   	9
#define R_RISCV_TLS_TPREL32   	10
#define R_RISCV_TLS_TPREL64   	11
#define R_RISCV_BRANCH        	16   
#define R_RISCV_JAL           	17   
#define R_RISCV_CALL          	18   
#define R_RISCV_CALL_PLT      	19   
#define R_RISCV_GOT_HI20      	20   
#define R_RISCV_TLS_GOT_HI20  	21
#define R_RISCV_TLS_GD_HI20   	22
#define R_RISCV_PCREL_HI20    	23   
#define R_RISCV_PCREL_LO12_I  	24   
#define R_RISCV_PCREL_LO12_S  	25   
#define R_RISCV_HI20          	26   
#define R_RISCV_LO12_I        	27   
#define R_RISCV_LO12_S        	28   
#define R_RISCV_TPREL_HI20    	29
#define R_RISCV_TPREL_LO12_I  	30
#define R_RISCV_TPREL_LO12_S  	31
#define R_RISCV_RELAX         	51   
#define R_RISCV_ALIGN         	52   

#define ELF64_R_SYM(info)    	((info) >> 32)   				// Extract symbol index from relocation info
#define ELF64_REL_TYPE(info)   	((info) & 0xFFFFFFFF)   		// Extract relocation type from relocation info
#define ELF64_R_INFO(S, T) 		((((uint64_t)(S)) << 32) + (T)) // Construct relocation info from symbol index and type

#define ELF64_ST_BIND(info)   	((info) >> 4)
#define ELF64_ST_TYPE(info)   	((info) & 0xF)
#define ELF64_ST_INFO(B, T) 	(((B) << 4) + ((T) & 0xF))

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

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
} elf64_ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;   // Offset in file
    uint64_t p_vaddr;    // Virtual address in memory
    uint64_t p_paddr;
    uint64_t p_filesz;   // Bytes in file
    uint64_t p_memsz;    // Bytes in memory
    uint64_t p_align;
} elf64_phdr;

typedef struct {
    uintptr_t  	r_offset;  	// 8 bytes: Where to apply the relocation
    uintptr_t 	r_info;    	// 8 bytes: Symbol + type
    intptr_t 	r_addend; 	// 8 bytes: Addend to add to symbol value
} elf64_rela;

typedef struct {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} elf64_sym;

typedef struct {
    uint32_t sh_name;       // Offset to section name in the section header string table
    uint32_t sh_type;       // Section type (e.g., SHT_PROGBITS, SHT_SYMTAB)
    uint64_t sh_flags;      // Section attributes (e.g., SHF_ALLOC, SHF_EXECINSTR)
    uint64_t sh_addr;       // Virtual address in memory (for loaded sections)
    uint64_t sh_offset;     // Offset in the file
    uint64_t sh_size;       // Size of the section
    uint32_t sh_link;       // Link to another section (e.g., symbol table link)
    uint32_t sh_info;       // Additional section information (depends on type)
    uint64_t sh_addralign;  // Section alignment
    uint64_t sh_entsize;    // Entry size if section holds table (e.g., symbol table)
} elf64_shdr;

typedef struct {
    int64_t d_tag;
    union {
        uint64_t d_val;
        uint64_t d_ptr;
    } d_un;
} elf64_dyn;


namespace rvm64::elf {
	// ========= helpers/state =========
	static inline uint64_t align_up(uint64_t x, uint64_t a) { return (x + a - 1) & ~(a - 1); }
	static inline bool in_img(uint64_t off, uint64_t len, uint64_t img_size) {
		return off <= img_size && len <= img_size - off;
	}

	static uint64_t g_elf_base = 0;   // min p_vaddr of PT_LOAD
	static uint64_t g_img_size = 0;   // relocated image size (copied into vm buffer)

	// ========= loader =========
	_native void load_elf_image(uintptr_t image_data, size_t image_size) {
		const uint8_t* file = (const uint8_t*)image_data;
		const elf64_ehdr* fe = (const elf64_ehdr*)file;

		if (!(file[0]==0x7F && file[1]=='E' && file[2]=='L' && file[3]=='F')) {
			CSR_SET_TRAP(nullptr, image_bad_type, 0, 0, 1);
		}
		if (fe->e_ident[EI_CLASS] != ELFCLASS64 || fe->e_ident[EI_DATA] != 1 /*LE*/ || fe->e_machine != EM_RISC) {
			CSR_SET_TRAP(nullptr, image_bad_type, 0, 0, 1);
		}
		if ((uint64_t)fe->e_phoff + (uint64_t)fe->e_phentsize * fe->e_phnum > image_size) {
			CSR_SET_TRAP(nullptr, image_bad_load, 0, 0, 1);
		}

		const elf64_phdr* fph = (const elf64_phdr*)(file + fe->e_phoff);

		// Compute load range
		uint64_t base = UINT64_MAX, end = 0;
		for (int i = 0; i < fe->e_phnum; ++i) {
			const auto& ph = fph[i];
			if (ph.p_type == PT_LOAD) {
				base = MIN(base, ph.p_vaddr);
				end  = MAX(end,  ph.p_vaddr + ph.p_memsz);
			}
		}
		if (base == UINT64_MAX || end <= base) {
			CSR_SET_TRAP(nullptr, image_bad_load, 0, 0, 1);
		}

		// Mirror headers at offset 0 so ehdr/phdrs are readable in relocated image
		uint64_t header_span = fe->e_phoff + (uint64_t)fe->e_phentsize * fe->e_phnum;
		if (header_span < fe->e_ehsize) header_span = fe->e_ehsize;
		if (header_span > image_size) header_span = image_size;

		uint64_t need = MAX(header_span, end - base);
		uint64_t img_size = align_up(need, 0x1000);

		uint8_t* img = (uint8_t*)VirtualAlloc(nullptr, img_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!img) {
			CSR_SET_TRAP(nullptr, image_bad_load, 0, 0, 1);
		}

		x_memset(img, 0, img_size);
		x_memcpy(img, file, header_span);

		// Copy PT_LOAD segments into (p_vaddr - base)
		for (int i = 0; i < fe->e_phnum; ++i) {
			const auto& ph = fph[i];
			if (ph.p_type != PT_LOAD) continue;

			if ((uint64_t)ph.p_offset + ph.p_filesz > image_size) {
				VirtualFree(img, 0, MEM_RELEASE);
				CSR_SET_TRAP(nullptr, image_bad_load, 0, 0, 1);
			}
			uint64_t dest_off = ph.p_vaddr - base;
			if (!in_img(dest_off, ph.p_memsz, img_size)) {
				VirtualFree(img, 0, MEM_RELEASE);
				CSR_SET_TRAP(nullptr, image_bad_load, 0, 0, 1);
			}
			if (ph.p_filesz) x_memcpy(img + dest_off, file + ph.p_offset, ph.p_filesz);
			// bss is already zeroed (memsz - filesz)
		}

		// Publish to VM buffer
		if (img_size > CHANNEL_BUFFER_SIZE) {
			VirtualFree(img, 0, MEM_RELEASE);
			CSR_SET_TRAP(nullptr, image_bad_load, 0, 0, 1);
		}

		x_memcpy((void*)vmcs->channel.view.buffer, img, img_size);
		VirtualFree(img, 0, MEM_RELEASE);

		g_elf_base = base;
		g_img_size = img_size;
	}

	// ========= reloc + PLT + entry =========
	static void apply_relative_relocs(uint8_t* img) {
		auto* ehdr = (elf64_ehdr*)img;
		auto* phdr = (elf64_phdr*)(img + ehdr->e_phoff);

		// Find PT_DYNAMIC
		uint64_t dyn_vaddr = 0, dyn_size = 0;
		for (int i = 0; i < ehdr->e_phnum; ++i) { // typo fix later
			if (phdr[i].p_type == PT_DYNA /* PT_DYNAMIC */) {
				dyn_vaddr = phdr[i].p_vaddr;
				dyn_size  = phdr[i].p_memsz;
				break;
			}
		}
		if (!dyn_vaddr || !dyn_size) return;

		uint64_t dyn_off = dyn_vaddr - g_elf_base;
		if (!in_img(dyn_off, sizeof(elf64_dyn), g_img_size)) return;

		uint64_t rela_va=0, rela_sz=0, rela_ent=sizeof(elf64_rela);
		for (elf64_dyn* d = (elf64_dyn*)(img + dyn_off);
				in_img((uint8_t*)d - img, sizeof(*d), g_img_size) && d->d_tag != DT_NULL; ++d) {

			if (d->d_tag == DT_RELA)     rela_va  = d->d_un.d_ptr;
			else if (d->d_tag == DT_RELASZ)  rela_sz  = d->d_un.d_val;
			else if (d->d_tag == DT_RELAENT) rela_ent = d->d_un.d_val ? d->d_un.d_val : sizeof(elf64_rela);
		}
		if (!rela_va || !rela_sz || !rela_ent) return;

		uint64_t rela_off = rela_va - g_elf_base;
		size_t n = (size_t)(rela_sz / rela_ent);

		for (size_t i = 0; i < n; ++i) {
			uint64_t off = rela_off + i * rela_ent;
			if (!in_img(off, sizeof(elf64_rela), g_img_size)) {
				break;
			}
			const elf64_rela* r = (const elf64_rela*)(img + off);
			uint32_t rtype = ELF64_REL_TYPE(r->r_info);

			if (rtype == R_RISCV_RELATIVE) {
				uint64_t where_off = r->r_offset - g_elf_base;

				if (!in_img(where_off, 8, g_img_size)) {
					continue;
				}
				*(uint64_t*)(img + where_off) = g_elf_base + (uint64_t)r->r_addend;
			}
		}
	}

	static uint64_t find_entry(uint8_t* img) {
		auto* ehdr = (elf64_ehdr*)img;
		auto* phdr = (elf64_phdr*)(img + ehdr->e_phoff);

		// Prefer e_entry if present
		if (ehdr->e_entry) return ehdr->e_entry;

		// Find PT_DYNAMIC
		uint64_t dyn_vaddr = 0;
		for (int i = 0; i < ehdr->e_phnum; ++i) {
			if (phdr[i].p_type == PT_DYNA) { dyn_vaddr = phdr[i].p_vaddr; break; }
		}
		if (!dyn_vaddr) return 0;

		uint64_t dyn_off = dyn_vaddr - g_elf_base;
		if (!in_img(dyn_off, sizeof(elf64_dyn), g_img_size)) return 0;

		// Pull tables
		uint64_t symtab_va=0, strtab_va=0, syment=sizeof(elf64_sym), strsz=0;
		for (elf64_dyn* d = (elf64_dyn*)(img + dyn_off);
				in_img((uint8_t*)d - img, sizeof(*d), g_img_size) && d->d_tag != DT_NULL; ++d) {
			if (d->d_tag == DT_SYMTAB)  symtab_va = d->d_un.d_ptr;
			else if (d->d_tag == DT_STRTAB)  strtab_va = d->d_un.d_ptr;
			else if (d->d_tag == DT_SYMENT)  syment    = d->d_un.d_val ? d->d_un.d_val : sizeof(elf64_sym);
			else if (d->d_tag == DT_STRSZ)   strsz     = d->d_un.d_val;
		}
		if (!symtab_va || !strtab_va) return 0;

		uint64_t sym_off = symtab_va - g_elf_base;
		uint64_t str_off = strtab_va - g_elf_base;
		if (!in_img(sym_off, sizeof(elf64_sym), g_img_size)) return 0;
		if (!in_img(str_off, 1, g_img_size)) return 0;
		if (strsz == 0 || !in_img(str_off, strsz, g_img_size)) strsz = g_img_size - str_off;

		// Walk bounded
		const uint64_t MAX_ITERS = 1u << 20;
		for (uint64_t i = 0, off = sym_off; i < MAX_ITERS && in_img(off, syment, g_img_size); ++i, off += syment) {
			const elf64_sym* s = (const elf64_sym*)(img + off);
			if (!s->st_value) continue;

			uint32_t name_off = s->st_name;
			if (name_off >= strsz) continue;
			const char* name = (const char*)(img + str_off + name_off);
			size_t remain = (size_t)(strsz - name_off);
			const void* nul = memchr(name, 0, remain);
			if (!nul) continue;

			if (strcmp(name, "_start") == 0 || strcmp(name, "main") == 0) {
				return s->st_value; // VADDR
			}
		}
		return 0;
	}

	static void patch_plt(uint8_t* img) {
		auto* ehdr = (elf64_ehdr*)img;
		auto* phdr = (elf64_phdr*)(img + ehdr->e_phoff);

		// Find PT_DYNAMIC
		uint64_t dyn_vaddr = 0;
		for (int i = 0; i < ehdr->e_phnum; ++i) {
			if (phdr[i].p_type == PT_DYNA) { dyn_vaddr = phdr[i].p_vaddr; break; }
		}
		if (!dyn_vaddr) return;

		uint64_t dyn_off = dyn_vaddr - g_elf_base;
		if (!in_img(dyn_off, sizeof(elf64_dyn), g_img_size)) return;

		uint64_t symtab_va=0, strtab_va=0, strsz=0, syment=sizeof(elf64_sym);
		uint64_t jmprel_va=0, pltrel_sz=0, plt_rel_kind=0;

		for (elf64_dyn* d = (elf64_dyn*)(img + dyn_off);
				in_img((uint8_t*)d - img, sizeof(*d), g_img_size) && d->d_tag != DT_NULL; ++d) {
			switch (d->d_tag) {
				case DT_SYMTAB:   symtab_va   = d->d_un.d_ptr; break;
				case DT_STRTAB:   strtab_va   = d->d_un.d_ptr; break;
				case DT_STRSZ:    strsz       = d->d_un.d_val; break;
				case DT_SYMENT:   syment      = d->d_un.d_val ? d->d_un.d_val : sizeof(elf64_sym); break;
				case DT_JMPREL:   jmprel_va   = d->d_un.d_ptr; break;
				case DT_PLTRELSZ: pltrel_sz   = d->d_un.d_val; break;
				case DT_PLTREL:   plt_rel_kind= d->d_un.d_val; break;
				default: break;
			}
		}
		if (!jmprel_va || !pltrel_sz || plt_rel_kind != DT_RELA || !symtab_va || !strtab_va) return;

		uint64_t rela_off   = jmprel_va - g_elf_base;
		uint64_t symtab_off = symtab_va - g_elf_base;
		uint64_t strtab_off = strtab_va - g_elf_base;
		if (!in_img(rela_off, pltrel_sz, g_img_size)) return;
		if (!in_img(symtab_off, sizeof(elf64_sym), g_img_size)) return;
		if (!in_img(strtab_off, 1, g_img_size)) return;
		if (strsz == 0 || !in_img(strtab_off, strsz, g_img_size)) strsz = g_img_size - strtab_off;

		size_t n = pltrel_sz / sizeof(elf64_rela);
		for (size_t i = 0; i < n; ++i) {
			uint64_t off = rela_off + i * sizeof(elf64_rela);
			if (!in_img(off, sizeof(elf64_rela), g_img_size)) break;
			const elf64_rela* r = (const elf64_rela*)(img + off);

			uint32_t rtype = ELF64_REL_TYPE(r->r_info);
			if (rtype != R_RISCV_JUMP_SLOT && rtype != R_RISCV_CALL_PLT) continue;

			uint32_t sym_idx = (uint32_t)ELF64_R_SYM(r->r_info);
			uint64_t s_off = symtab_off + (uint64_t)sym_idx * syment;
			if (!in_img(s_off, sizeof(elf64_sym), g_img_size)) continue;

			const elf64_sym* s = (const elf64_sym*)(img + s_off);
			uint32_t name_off = s->st_name;
			if (name_off >= strsz) continue;

			const char* name = (const char*)(img + strtab_off + name_off);
			size_t remain = (size_t)(strsz - name_off);
			if (!memchr(name, 0, remain)) continue;

			void* target = rvm64::rvni::resolve_ucrt_import(name);
			if (!target) {
				CSR_SET_TRAP(nullptr, image_bad_symbol, 0, (uintptr_t)name, 1);
			}

			uint64_t where_off = r->r_offset - g_elf_base;
			if (!in_img(where_off, 8, g_img_size)) continue;
			*(uint64_t*)(img + where_off) = (uint64_t)target;
		}
	}

	_native void patch_elf_plt_and_set_entry() {
		uint8_t* img = (uint8_t*)vmcs->channel.view.buffer;
		if (!img || g_img_size == 0) {
			CSR_SET_TRAP(nullptr, image_bad_load, 0, 0, 1);
		}

		auto* ehdr = (elf64_ehdr*)img;
		if (ehdr->e_ident[0] != 0x7F || ehdr->e_ident[1] != 'E' || ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F') {
			CSR_SET_TRAP(nullptr, image_bad_type, 0, 0, 1);
		}
		if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
			CSR_SET_TRAP(nullptr, image_bad_type, 0, 0, 1);
		}

		apply_relative_relocs(img);
		patch_plt(img);

		// 3) set entry
		uint64_t entry_vaddr = find_entry(img);
		if (!entry_vaddr) {
			CSR_SET_TRAP(nullptr, image_bad_symbol, 0, (uintptr_t)"<no entry>", 1);
		}

		uint64_t pc_off = entry_vaddr - g_elf_base;
		if (!in_img(pc_off, 4, g_img_size)) {
			CSR_SET_TRAP(nullptr, image_bad_load, 0, 0, 1);
		}

		vmcs->pc = (uintptr_t)(img + pc_off);
	}
};
#endif // VMELF_H
