#ifndef VMCS_H
#define VMCS_H
#include <windows.h>
#include <stdint.h>
#include <setjmp.h>

#include "vmcommon.hpp"


typedef struct {
	HANDLE handle;
	DWORD pid;
	UINT_PTR address;
	SIZE_T size;
} win_process;

// NOTE: 
// - who is allocating/destroying the buffer?
// - who is loading/mapping the ELF?
typedef struct _vmcs {
    uint64_t magic1, magic2;
	uint64_t thread_id;

	struct {
		uint64_t self;
		uint64_t ready_ptr;	
		uint64_t size_ptr;
		uint64_t write_size_ptr;
	} ptrs;

	struct {
		uint64_t buffer;
		uint64_t size;
		uint64_t write_size;   
		volatile uint64_t ready;   
	} proc;
							   
	struct {
		uint64_t pc;
		uint64_t vscratch[8];
		uint64_t vregs[32];
		uint64_t vstack[32];

		struct {
			uintptr_t m_epc;
			uintptr_t m_cause;
			uintptr_t m_status;
			uintptr_t m_tval;
		} csr;
	} hdw;

	uint64_t load_rsv_addr;
	uint64_t load_rsv_valid;

	jmp_buf trap_handler;
	jmp_buf exit_handler;

	int cache;
	int trap;
	int halt;
} vmcs_t;


struct intel_t {
    uint64_t rip, rsp, rax, rbx, rcx, rdx, rsi, rdi, rbp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rflags;
};

#include "vmport.hpp"
#ifdef __cplusplus
VM_EXTERN_C {
#endif

	void save_host_context();
	void restore_host_context();
	void save_vm_context();
	void restore_vm_context();

	VM_DATA vmcs_t* vmcs = { };
	VM_DATA HANDLE vmcs_mutex = 0;
	VM_DATA HANDLE veh_handle = 0;

	VM_DATA intel_t host_context = { };
	VM_DATA intel_t vm_context = { };

	extern const uintptr_t dispatch_table[256];

#ifdef __cplusplus
}
#endif
#endif //VMCS_H
