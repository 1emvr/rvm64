#ifndef VMCS_H
#define VMCS_H
#include <windows.h>
#include <stdint.h>
#include <setjmp.h>

#include "vmcommon.hpp"

typedef struct {
	uintptr_t start;
	uintptr_t end;
} vm_range_t;


typedef struct {
	uint8_t *address;
	size_t size;
	uintptr_t stat;
} vm_buffer_t;


typedef struct {
	uint8_t *address;
	uintptr_t base_vaddr;
	uintptr_t entry;
	size_t size;
	vm_range_t plt;
} vm_process_t;


struct intel_t {
    uint64_t rip, rsp, rax, rbx, rcx, rdx, rsi, rdi, rbp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rflags;
};

typedef struct {
	uintptr_t pc;
	uintptr_t vscratch[32];
	uintptr_t vregs[32];
	uintptr_t vstack[VSTACK_MAX_CAPACITY];

	uintptr_t load_rsv_addr;
	uintptr_t load_rsv_valid;

	vm_process_t process;
	jmp_buf trap_handler;
	jmp_buf exit_handler;

	struct {
		uintptr_t m_epc;
		uintptr_t m_cause;
		uintptr_t m_status;
		uintptr_t m_tval;
	} csr;

	int trap;
	int cache;
	int halt;
} vmcs_t;


#ifdef __cplusplus
_externc {
#endif

	void save_host_context();
	void restore_host_context();
	void save_vm_context();
	void restore_vm_context();

	_data vmcs_t *vmcs = nullptr;
	_data HANDLE vmcs_mutex = 0;
	_data HANDLE veh_handle = 0;

	_data intel_t host_context = { };
	_data intel_t vm_context = { };

	extern const uintptr_t dispatch_table[256];

#ifdef __cplusplus
}
#endif
#endif //VMCS_H
