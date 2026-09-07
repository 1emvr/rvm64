#include <windows.h>
#include "vmmain.hpp"

// just realized that " forever threads " will need to have their own memory. 
// we can separate one-time runs from the forever threads. this way there is no deadlock

#define MAX_VM_THREADS 5
struct PACKET_SEG { 
	UINT_PTR 	image_offset [MAX_VM_THREADS]; 
	UINT_PTR 	param_offset [MAX_VM_THREADS];
	SIZE_T 		count; 
};


NATIVE_CALL BOOL is_elf (_In_ UINT_PTR base) {
	return base [EI_MAG0] == ELFMAG0 && base [EI_MAG1] == ELFMAG1 && 
			base [EI_MAG2] == ELFMAG2 && base [EI_MAG3] == ELFMAG3;
}


NATIVE_CALL VOID thread_main () {
	return;
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



NATIVE_CALL BOOL process_packets ( 
		_Inout_ 	UINT_PTR* 		data,
		_Inout_ 	UINT_PTR* 		data_sz,
		_Out_ 		PACKET_SEG* 	new_vms)
{
	UINT8 *image_base 	= (UINT8*)*data;
	UINT_PTR remaining 	= *data_sz;
	UINT_PTR offset 	= 0;

#define update_arena_space (sz) 						\
	if (remaining - sz <= 0) {/*idk do something...*/}  \
	offset 		+= sz; 									\
	image_base 	+= sz; 									\
	remaining 	-= sz; 

	UINT_PTR n_threads = image_base [0]; 
	update_arena_space (sizeof (UINT_PTR));

	if (n_threads == 0 || n_threads > MAX_VM_THREADS) {
		return false;
	}
	for (int i = 0; i < n_threads; i++) { 
		UINT_PTR param_sz = image_base [0]; // packed data is [param (size/data), elf (size/data), (_pt_load_space)], ... 
											
		if (param_sz != 0) {						
			new_vms->param_offset [i] = offset; // param offset starts at the size so that it's quickly available to read
		}

		update_arena_space (sizeof (UINT_PTR) + param_sz);
		new_vms->image_offset [i] = offset; 

		UINT_PTR elf_sz = image_base [0];
		update_arena_space (sizeof (UINT_PTR)); // packed elf size for efficiency

		if (!is_elf (image_base) || image_base [EI_CLASS] != ELFCLASS64) {
			return false;
		}

		UINT64 runtime_sz = elf_runtime_size (image_base, nullptr);
		if (elf_sz < runtime_sz) {

		}
		new_vms->count += 1;
	}
	return true;
}


NATIVE_CALL VOID rvm64_main (
		_In_ const UINT_PTR* data, 	// data points to a pre-made arena
		_In_ const UINT_PTR* data_sz) 
{
	HANDLE threads [MAX_VM_THREADS] = { };		
	PACKET_SEG new_vms = { };

	if (!process_packets (data, data_sz, &new_vms)) { // track param_base / elf data offsets 
		goto defer;
	}
	if (new_vms.count == 0) {
		return;
	}

	for (int i = 0; i < new_vms.count; i++) {
		UINT_PTR image_base = *data + new_vms.image_offset [i];
		UINT_PTR param_base = *data + new_vms.param_offset [i];

		if (param_base [0] == 0) {
			param_base = nullptr;
		}

		threads [i] = CreateThread (nullptr, 0, vm_thread (image_base), param_base, 0, nullptr); // TODO: redesign vmcs to handle multiple threads
	}

	WaitForMultipleObjects (new_vms.count, &threads, true, 5000);
	// post_thread_response () ??
	//
defer:
	// arena_release () ??
}


NATIVE_CALL VOID rvm64_start (
		_In_ const UINT_PTR* data,
		_In_ const UINT_PTR* data_sz) // should rvm64_start handle the arena, or leave it to another module?
{
	VMCS instance = { };
	vmcs = &instance; // a global vmcs instance to track everything (?)

	rvm64_init (&vmcs->ctx); 
	rvm64_save_reg (&vmcs->ctx->host_ctx);

	rvm64_main (data, data_sz); // TODO: arena_allocate () 

	rvm64_load_reg (&vmcs->ctx->host_ctx);
	rvm64_release (&vmcs->ctx); // release context
}
