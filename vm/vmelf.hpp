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
#define ELF64_R_INFO(S, T) 		((((UINT_PTR)(S)) << 32) + (T)) // Construct relocation info from symbol index and type

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
    UINT8  		e_ident [EI_NIDENT]; // ELF magic, class, data, etc.
    UINT16 		e_type;
    UINT16 		e_machine;
    UINT32 		e_version;
    UINT_PTR 	e_entry;    // Virtual address of entry point
    UINT_PTR 	e_phoff;    // Program header offset
    UINT_PTR 	e_shoff;
    UINT32 		e_flags;
    UINT16 		e_ehsize;
    UINT16 		e_phentsize;
    UINT16 		e_phnum;    // Number of program headers
    UINT16 		e_shentsize;
    UINT16 		e_shnum;
    UINT16 		e_shstrndx;
} ELF64_EHDR;

typedef struct {
    UINT32 		p_type;
    UINT32 		p_flags;
    UINT_PTR 	p_offset;   // Offset in file
    UINT_PTR 	p_vaddr;    // Virtual address in memory
    UINT_PTR 	p_paddr;
    UINT_PTR 	p_filesz;   // Bytes in file
    UINT_PTR 	p_memsz;    // Bytes in memory
    UINT_PTR 	p_align;
} ELF64_PHDR;

typedef struct {
    UINT_PTR  	r_offset;  	// 8 bytes: Where to apply the relocation
    UINT_PTR 	r_info;    	// 8 bytes: Symbol + type
    INTPTR 		r_addend; 	// 8 bytes: Addend to add to symbol value
} ELF64_RELA;

typedef struct {
    UINT32 		st_name;
    UINT8  		st_info;
    UINT8  		st_other;
    UINT16 		st_shndx;
    UINT_PTR 	st_value;
    UINT_PTR 	st_size;
} ELF64_SYM;

typedef struct {
    UINT32 		sh_name;       // Offset to section name in the section header string table
    UINT32 		sh_type;       // Section type (e.g., SHT_PROGBITS, SHT_SYMTAB)
    UINT_PTR 	sh_flags;      // Section attributes (e.g., SHF_ALLOC, SHF_EXECINSTR)
    UINT_PTR 	sh_addr;       // Virtual address in memory (for loaded sections)
    UINT_PTR 	sh_offset;     // Offset in the file
    UINT_PTR 	sh_size;       // Size of the section
    UINT32 		sh_link;       // Link to another section (e.g., symbol table link)
    UINT32 		sh_info;       // Additional section information (depends on type)
    UINT_PTR 	sh_addralign;  // Section alignment
    UINT_PTR 	sh_entsize;    // Entry size if section holds table (e.g., symbol table)
} ELF64_SHDR;

typedef struct {
    int64_t d_tag;
    union {
        UINT_PTR d_val;
        UINT_PTR d_ptr;
    } d_un;
} ELF64_DYN;


namespace rvm64::elf {
	static inline UINT_PTR AlignUp (UINT_PTR x, UINT_PTR a) { 
		return (x + a - 1) & ~(a - 1); 
	}
	static inline BOOL InImage (UINT_PTR off, UINT_PTR len, UINT_PTR size) {
		return off <= img_size && len <= size - off;
	}

	static UINT_PTR g_elf_base = 0;   // min p_vaddr of PT_LOAD
	static UINT_PTR g_img_size = 0;   // relocated image size (copied into vm buffer)

	NATIVE VOID LoadImage (UINT_PTR image_data, SIZE_T image_size) {
		const UINT8 *file = (const UINT8*)image_data;
		const ELF64_EHDR *fe = (const ELF64_EHDR*)file;

		UINT_PTR base = UINT64_MAX, end = 0;

		if (!(file [0]==0x7F && file [1]=='E' && file [2]=='L' && file [3]=='F')) {
			CSR_SET_TRAP(nullptr, image_bad_type, 0, 0, 1);
		}
		if (fe->e_ident [EI_CLASS] != ELFCLASS64 || fe->e_ident [EI_DATA] != 1 || fe->e_machine != EM_RISC) {
			CSR_SET_TRAP(nullptr, image_bad_type, 0, 0, 1);
		}
		if ((UINT_PTR)fe->e_phoff + (UINT_PTR)fe->e_phentsize * fe->e_phnum > image_size) {
			CSR_SET_TRAP(nullptr, image_bad_load, 0, 0, 1);
		}

		const ELF64_PHDR *fph = (const ELF64_PHDR*)(file + fe->e_phoff);

		for (int i = 0; i < fe->e_phnum; ++i) {
			const auto& ph = fph [i];
			if (ph.p_type == PT_LOAD) {
				base = MIN (base, ph.p_vaddr);
				end  = MAX (end,  ph.p_vaddr + ph.p_memsz);
			}
		}
		if (base == UINT64_MAX || end <= base) {
			CSR_SET_TRAP(nullptr, image_bad_load, 0, 0, 1);
		}

		// Mirror headers at offset 0 so ehdr/phdrs are readable in relocated image
		UINT_PTR header_span = fe->e_phoff + (UINT_PTR)fe->e_phentsize * fe->e_phnum;

		if (header_span < fe->e_ehsize) {
			header_span = fe->e_ehsize;
		}
		if (header_span > image_size) {
			header_span = image_size;
		}

		UINT_PTR need = MAX (header_span, end - base);
		UINT_PTR img_size = AlignUp (need, 0x1000);

		UINT8* img = (UINT8*)VirtualAlloc(nullptr, img_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!img) {
			CSR_SET_TRAP(nullptr, image_bad_load, 0, 0, 1);
		}

		x_memset(img, 0, img_size);
		x_memcpy(img, file, header_span);

		for (INT i = 0; i < fe->e_phnum; ++i) {
			const auto& ph = fph [i];

			if (ph.p_type != PT_LOAD) {
				continue;
			}
			if ((UINT_PTR)ph.p_offset + ph.p_filesz > image_size) {
				VirtualFree (img, 0, MEM_RELEASE);
				CSR_SET_TRAP (nullptr, image_bad_load, 0, 0, 1);
			}

			UINT_PTR dest_off = ph.p_vaddr - base;

			if (! InImage (dest_off, ph.p_memsz, img_size)) {
				VirtualFree (img, 0, MEM_RELEASE);
				CSR_SET_TRAP (nullptr, image_bad_load, 0, 0, 1);
			}
			if (ph.p_filesz) {
				x_memcpy(img + dest_off, file + ph.p_offset, ph.p_filesz);
			}
		}
		if (img_size > PROCESS_BUFFER_SIZE) {
			VirtualFree (img, 0, MEM_RELEASE);
			CSR_SET_TRAP (nullptr, image_bad_load, 0, 0, 1);
		}

		x_memcpy ((void*)vmcs->proc.buffer, img, img_size);
		vmcs->proc.write_size = img_size;
		VirtualFree (img, 0, MEM_RELEASE);

		g_elf_base = base;
		g_img_size = img_size;
	}

	// ========= reloc + PLT + entry =========
	static void ApplyRelativeOffsets (UINT8* img) {
		auto* ehdr = (elf64_ehdr*)img;
		auto* phdr = (elf64_phdr*)(img + ehdr->e_phoff);

		UINT_PTR dyn_vaddr = 0, dyn_size = 0;

		for (int i = 0; i < ehdr->e_phnum; ++i) { 
			if (phdr [i].p_type == PT_DYNA) {
				dyn_vaddr = phdr [i].p_vaddr;
				dyn_size  = phdr [i].p_memsz;
				break;
			}
		}
		if (!dyn_vaddr || !dyn_size) {
			return;
		}

		UINT_PTR dyn_off = dyn_vaddr - g_elf_base;
		UINT_PTR rela_va=0, rela_sz=0, rela_ent = sizeof (ELF64_RELA);

		if (!in_img(dyn_off, sizeof(elf64_dyn), g_img_size)) {
			return;
		}
		for (ELF64_DYN* d = (ELF64_DYN*)(img + dyn_off); 
				InImage ((UINT8*)d - img, sizeof(*d), g_img_size) 
				&& d->d_tag != DT_NULL; ++d) {

			if (d->d_tag == DT_RELA)     rela_va  = d->d_un.d_ptr;
			else if (d->d_tag == DT_RELASZ)  rela_sz  = d->d_un.d_val;
			else if (d->d_tag == DT_RELAENT) rela_ent = d->d_un.d_val ? d->d_un.d_val : sizeof(elf64_rela);
		}
		if (!rela_va || !rela_sz || !rela_ent) {
			return;
		}

		UINT_PTR rela_off = rela_va - g_elf_base;
		SIZE_T n = (SIZE_T)(rela_sz / rela_ent);

		for (SIZE_T i = 0; i < n; ++i) {
			UINT_PTR off = rela_off + i * rela_ent;

			if (! InImage (off, sizeof(elf64_rela), g_img_size)) {
				break;
			}
			const ELF64_RELA* r = (const ELF64_RELA*)(img + off);
			const UINT32 rtype = ELF64_REL_TYPE (r->r_info);

			if (rtype == R_RISCV_RELATIVE) {
				UINT_PTR where_off = r->r_offset - g_elf_base;

				if (! InImage (where_off, 8, g_img_size)) {
					continue;
				}
				*(UINT_PTR*)(img + where_off) = g_elf_base + (UINT_PTR)r->r_addend;
			}
		}
	}

	static UINT_PTR FindEntry (UINT8* img) {
		ELF64_EHDR *ehdr = (ELF64_EHDR*)img;
		ELF64_PHDR *phdr = (ELF64_PHDR*)(img + ehdr->e_phoff);

		UINT_PTR dyn_vaddr = 0;

		if (ehdr->e_entry) {
			return ehdr->e_entry;
		}
		for (int i = 0; i < ehdr->e_phnum; ++i) {
			if (phdr [i].p_type == PT_DYNA) { 
				dyn_vaddr = phdr [i].p_vaddr; 
				break; 
			}
		}
		if (!dyn_vaddr) {
			return 0;
		}

		UINT_PTR dyn_off = dyn_vaddr - g_elf_base;
		if (! InImage (dyn_off, sizeof(elf64_dyn), g_img_size)) {
			return 0;
		}

		// Pull tables
		UINT_PTR symtab_va=0, strtab_va=0, syment=sizeof(elf64_sym), strsz=0;

		for (elf64_dyn* d = (elf64_dyn*)(img + dyn_off); in_img((UINT8*)d - img, sizeof(*d), g_img_size) && d->d_tag != DT_NULL; ++d) {
			if (d->d_tag == DT_SYMTAB)  symtab_va = d->d_un.d_ptr;
			else if (d->d_tag == DT_STRTAB)  strtab_va = d->d_un.d_ptr;
			else if (d->d_tag == DT_SYMENT)  syment    = d->d_un.d_val ? d->d_un.d_val : sizeof(elf64_sym);
			else if (d->d_tag == DT_STRSZ)   strsz     = d->d_un.d_val;
		}
		if (!symtab_va || !strtab_va) return 0;

		UINT_PTR sym_off = symtab_va - g_elf_base;
		UINT_PTR str_off = strtab_va - g_elf_base;

		if (!in_img(sym_off, sizeof(elf64_sym), g_img_size)) return 0;
		if (!in_img(str_off, 1, g_img_size)) return 0;
		if (strsz == 0 || !in_img(str_off, strsz, g_img_size)) strsz = g_img_size - str_off;

		// Walk bounded
		const UINT_PTR MAX_ITERS = 1u << 20;

		for (UINT_PTR i = 0, off = sym_off; i < MAX_ITERS && in_img(off, syment, g_img_size); ++i, off += syment) {
			const elf64_sym* s = (const elf64_sym*)(img + off);
			if (!s->st_value) continue;

			UINT32 name_off = s->st_name;
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

	static VOID PatchPLT (UINT8* img) {
		auto* ehdr = (ELF64_EHDR*)img;
		auto* phdr = (ELF64_PHDR*)(img + ehdr->e_phoff);

		UINT_PTR dyn_vaddr = 0;

		for (INT i = 0; i < ehdr->e_phnum; ++i) { // Find PT_DYNAMIC
			if (phdr [i].p_type == PT_DYNA) { 
				dyn_vaddr = phdr [i].p_vaddr; 
				break; 
			}
		}
		if (!dyn_vaddr) {
			return;
		}

		UINT_PTR dyn_off = dyn_vaddr - g_elf_base;
		if (! in_img (dyn_off, sizeof (elf64_dyn), g_img_size)) {
			return;
		}

		UINT_PTR symtab_va=0, strtab_va=0, strsz=0, syment = sizeof (elf64_sym);
		UINT_PTR jmprel_va=0, pltrel_sz=0, plt_rel_kind=0;

		for (elf64_dyn* d = (elf64_dyn*)(img + dyn_off) {
				in_img((UINT8*)d - img, sizeof (*d), g_img_size) && d->d_tag != DT_NULL; ++d);
				switch (d->d_tag) {
					case DT_SYMTAB:   symtab_va   = d->d_un.d_ptr; break;
					case DT_STRTAB:   strtab_va   = d->d_un.d_ptr; break;
					case DT_STRSZ:    strsz       = d->d_un.d_val; break;
					case DT_JMPREL:   jmprel_va   = d->d_un.d_ptr; break;
					case DT_PLTRELSZ: pltrel_sz   = d->d_un.d_val; break;
					case DT_PLTREL:   plt_rel_kind= d->d_un.d_val; break;
					case DT_SYMENT:   syment      = 
					{
						d->d_un.d_val ? d->d_un.d_val : sizeof (elf64_sym); 
						break;
					}
					default: 
						break;
			}
		}
		if (!jmprel_va || !pltrel_sz || plt_rel_kind != DT_RELA || !symtab_va || !strtab_va) {
			return;
		}

		UINT_PTR rela_off   = jmprel_va - g_elf_base;
		UINT_PTR symtab_off = symtab_va - g_elf_base;
		UINT_PTR strtab_off = strtab_va - g_elf_base;

		if (!in_img (rela_off, pltrel_sz, g_img_size) ||
			!in_img (symtab_off, sizeof (elf64_sym), g_img_size) ||
			!in_img (strtab_off, 1, g_img_size)) {
			return;
		}
		if (strsz == 0 || !in_img(strtab_off, strsz, g_img_size)) {
			strsz = g_img_size - strtab_off;
		}

		SIZE_T n = pltrel_sz / sizeof (elf64_rela);

		for (SIZE_T i = 0; i < n; ++i) {
			UINT_PTR off = rela_off + i * sizeof (elf64_rela);

			if (!in_img(off, sizeof (elf64_rela), g_img_size)) {
				break;
			}

			const ELF64_RELA* r = (const ELF64_RELA*)(img + off);
			UINT32 rtype = ELF64_REL_TYPE(r->r_info);

			if (rtype != R_RISCV_JUMP_SLOT && rtype != R_RISCV_CALL_PLT) {
				continue;
			}

			UINT32 sym_idx = (UINT32)ELF64_R_SYM(r->r_info);
			UINT_PTR s_off = symtab_off + (UINT_PTR)sym_idx * syment;

			if (!in_img(s_off, sizeof (elf64_sym), g_img_size)) {
				continue;
			}

			const ELF64_SYM* s = (const ELF64_SYM*)(img + s_off);
			UINT32 name_off = s->st_name;

			if (name_off >= strsz) {
				continue;
			}

			const CHAR* name 	= (const CHAR*)(img + strtab_off + name_off);
			const SIZE_T remain = (const SIZE_T)(strsz - name_off);

			if (!memchr(name, 0, remain)) {
				continue;
			}

			LPVOID target = ResolveUCRTImport(name);
			if (!target) {
				CSR_SET_TRAP(nullptr, image_bad_symbol, 0, (UINT_PTR)name, 1);
			}

			UINT_PTR where_off = r->r_offset - g_elf_base;

			if (!in_img(where_off, 8, g_img_size)) {
				continue;
			}

			*(UINT_PTR*)(img + where_off) = (UINT_PTR)target;
		}
	}

	NATIVE VOID PatchAndSetEntry () {
		UINT8 *img = (UINT8*)vmcs->proc.buffer;
		ELF64_EHDR *ehdr = (ELF64_EHDR*)img;

		if (! img || imgSize == 0) {
			CSR_SET_TRAP(nullptr, ImageBadLoad, 0, 0, 1);
		}
		if (ehdr->e_ident [0] != 0x7F || ehdr->e_ident [1] != 'E' || ehdr->e_ident [2] != 'L' || ehdr->e_ident [3] != 'F') {
			CSR_SET_TRAP (nullptr, ImageBadType, 0, 0, 1);
		}
		if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
			CSR_SET_TRAP (nullptr, ImageBadType, 0, 0, 1);
		}

		ApplyRelativeOffsets (img);
		PatchPLT(img);

		UINT_PTR entry = FindEntry (img);
		UINT_PTR pcOff = entry - base;

		if (! entry) {
			CSR_SET_TRAP (nullptr, image_bad_symbol, 0, (UINT_PTR)"no entry", 1);
		}
		if (! InImage (pcOff, 4, imgSize)) {
			CSR_SET_TRAP (nullptr, image_bad_load, 0, 0, 1);
		}

		vmcs->hdw->pc = (UINT_PTR)(img + pcOff);
		VmEntry ();
	}
};
#endif // VMELF_H
