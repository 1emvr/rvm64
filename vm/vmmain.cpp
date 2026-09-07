#include <windows.h>
#include "vmmain.hpp"

// just realized that " forever threads " will need to have their own memory. 
// we can separate one-time runs from the forever threads. this way there is no deadlock

NATIVE_CALL BOOL is_elf (_In_ const UINT8 *base) {
	return base [EI_MAG0] == ELFMAG0 && base [EI_MAG1] == ELFMAG1 && 
			base [EI_MAG2] == ELFMAG2 && base [EI_MAG3] == ELFMAG3;
}


NATIVE_CALL UINT64 elf_runtime_size (
		_In_ 	const 	UINT8  	*base, 
		_Inout_ 		UINT64 	*out_align)
{
	const ELF64_EHDR *ehdr = (const ELF64_EHDR*)base;
	const ELF64_PHDR *phdr = (const ELF64_PHDR*)(base + ehdr->e_phoff);

	UINT64 lo = (UINT64)-1, hi = 0, align = 0x1000;

	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr [i].p_type != PT_LOAD) {
			continue;
		}

		UINT64 seg_lo = phdr [i].p_vaddr;
		UINT64 seg_hi = phdr [i].p_vaddr + phdr [i].p_memsz;
		UINT64 p_align = phdr [i].p_align;

		if (p_align > align) { align = p_align; }
		if (seg_lo < lo) 	 { lo = seg_lo; }
		if (seg_hi > hi) 	 { hi = seg_hi; }
	}

	lo &= ~(align -1);
	hi = (hi + align -1) & ~(align -1);

	if (out_align) *out_align = align;
	return hi - lo;
}


NATIVE_CALL UINT64 elf_image_size (_In_ const UINT8 *base) {
	const ELF64_EHDR *ehdr =  (const ELF64_EHDR *)base;
	UINT64 max = sizeof (ELF64_EHDR);

	if (ehdr->phoff) {		
		UINT64 end = ehdr->eh_phoff + (UINT64)(ehde->e_phnum * ehdr->e_phentsize);
		if (end > max) max = end;

		const ELF64_PHDR *phdr = (const ELF64_PHDR *)(base + ehdr->e_phoff);

		for (int i = 0; i < ehdr->e_phnum; i++) {
			UINT64 end = phdr [i]. ph_offset + phdr [i].p_filesz;
			if (end > max) max = end;
		}
	}
	if (ehdr->e_shoff) {
		UINT64 end = ehdr->e_shoff + (UINT64)(ehdr->e_shnum * ehdr->e_shentsize);
		if (end > max) max = end;

		const ELF64_SHDR *shdr = (const ELF64_SHDR *)base + ehdr->e_shoff;

		for (int i = 0; i < ehdr->e_shnum; i++) {
			if (shdr [i].sh_type == SHT_NOBITS) {
				continue;
			}

			UINT64 end2 = shdr [i].sh_offset + shdr [i].sh_size;
			if (end2 > max) max = end2;
		}
	}
	return max;
}


NATIVE_CALL BOOL process_packets (_Inout_ Arena *a) {
	UINT8 *img_base = a->data;
	UINT64 n_threads = (UINT64)img_base [0]; 
	
#define update_arena (b, o, sz) \
	b += sz;					\
	o += sz;					

	update_arena (img_base, a->offset, sizeof (UINT64)); // one-time thread count
	if (n_threads == 0 || n_threads > MAX_VM_THREADS) {
		return false;
	}

	for (int i = 0; i < n_threads; i++) {  // calculate size for all threads
		UINT64 param_sz = img_base [0]; 

		update_arena (img_base, a->offset, sizeof (UINT64) + param_sz);
		if (!is_elf (img_base) || img_base [EI_CLASS] != ELFCLASS64) {
			return false; 
		}

		a->entries [i].runtime_sz 	= elf_runtime_size (img_base, nullptr);
		a->entries [i].packed_sz 	= elf_image_size (img_base);

		update_arena (img_base, a->offset, a->entries [i].packed_sz);
	}

	UINT64 total = 0;

	for (int i = 0; i < n_threads; i++) {
		total += a->entries [i].runtime_sz;
	}
	if (total > a->capacity) {
		// arena_realloc (a, total);
	}

	a->offset = 0;
	return true;
}


VOID NATIVE_CALL thread_main (LPVOID parameters) {
	ThreadArgs *args = *(ThreadArgs **)parameters
	return;
}


VOID NATIVE_CALL rvm64_main (_In_ Arena* a) {
	if (!process_packets (a)) 		goto defer;
	if (a->count == 0) 				goto defer;
	if (a->count > MAX_VM_THREADS) 	goto defer;

	for (SIZE_T i = 0; i < a->count; i++) {
		thread_args [i].img_base 	= a->data + a->entires [i].elf_off;
		thread_args [i].param_base 	= a->data + a->entries [i].param_offset;

		if (param_base [0] == 0) param_base = nullptr;

		threads [i] = CreateThread (nullptr, 0, (LPTHREAD_START_ROUTINE)vm_thread, &thread_args[i], 0, nullptr); // TODO: redesign vmcs to handle multiple threads
	}

	DWORD result = WaitForMultipleObjects ((DWORD)a->count, threads, true, INFINITE); // infinite branch where nothing should loop

	for (SIZE_T i = 0; i < a->count; i++) {
		if (threads [i]) {
			CloseHandle (threads [i]);
			HeapFree (threads [i]);
		}
	}
	// post_thread_response () ??
defer:
	return;
}


VOID NATIVE_CALL rvm64_start (
		_In_ const UINT_PTR* data,
		_In_ const UINT_PTR* data_sz) // should rvm64_start handle the arena, or leave it to another module?
{
	VMCS instance = { };
	g_vmcs = &instance; // a global vmcs instance to track everything (?)

	rvm64_main (data, data_sz); // TODO: arena_allocate () 
}
