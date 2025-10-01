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


typedef struct {
	uint8_t *address;
	size_t size;
} vm_process;

typedef struct {
	uintptr_t m_epc;
	uintptr_t m_cause;
	uintptr_t m_status;
	uintptr_t m_tval;
} vm_csr;

typedef struct {
    uint64_t magic1, magic2;
    uint64_t thread_id;
    uint64_t self;

    struct {
        uint64_t buffer;
        uint64_t size;
        uint64_t write_size;   // values
    } view;

    // control (values)
    volatile uint64_t ready;   
    volatile uint64_t error;   

    // published addresses (shadow pointers -> where to WPM)
	uint64_t size_ptr;
    uint64_t ready_ptr;        // &ready
    uint64_t error_ptr;        // &error
    uint64_t write_size_ptr;   // &view.write_size
							   
	uint64_t vmcs_ptr;
	uint64_t vpc_ptr;
	uint64_t vstack_ptr;
	uint64_t vregs_ptr;
	uint64_t vprog_ptr;
} vm_channel;


// NOTE: channel embeded and on the stack
typedef struct _vmcs {
	vm_channel channel;

	uint64_t pc;
	uint64_t vscratch[8];
	uint64_t vregs[32];
	uint64_t vstack[32];

	vm_process process;
	vm_csr csr;

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
