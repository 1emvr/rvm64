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


typedef struct _vmcs {
    UINT64 magic1, magic2;
	UINT64 thread_id;

	UINT64 self;
	UINT64 ready_ptr;	
	UINT64 size_ptr;
	UINT64 write_size_ptr;

	typedef struct _hardware {
		UINT64 pc;
		UINT64 vscratch[8];
		UINT64 vregs[32];
		UINT64 vstack[32];

		struct {
			UINT_PTR m_epc;
			UINT_PTR m_cause;
			UINT_PTR m_status;
			UINT_PTR m_tval;
		} csr;

		jmp_buf trap_handler;
		jmp_buf exit_handler;
	} hardware;

	struct {
		UINT64 buffer;
		UINT64 size;
		UINT64 write_size;   
		volatile UINT64 ready;   
	} proc;
							   
	UINT64 load_rsv_addr;
	UINT64 load_rsv_valid;

	INT cache;
	INT trap;
	INT halt;
} vmcs_t;


struct intel_t {
    UINT64 rip, rsp, rax, rbx, rcx, rdx, rsi, rdi, rbp;
    UINT64 r8, r9, r10, r11, r12, r13, r14, r15;
    UINT64 rflags;
};

#include "vmport.hpp"

#ifdef __cplusplus
extern "C" {
#endif
	extern const UINT_PTR dispatch_table [256];

	VOID SaveHostContext ();
	VOID RestoreHostContext ();
	VOID SaveVmContext ();
	VOID RestoreVmContext ();

	VM_DATA VMCS* 	Vmcs 		= { };
	VM_DATA HANDLE 	VmcsMux 	= 0;
	VM_DATA HANDLE 	VehHandle 	= 0;

	VM_DATA INTEL HostContext 	= { };
	VM_DATA INTEL VmContext 	= { };
#ifdef __cplusplus
}
#endif
#endif //VMCS_H
