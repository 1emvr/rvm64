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

struct ucrt_alias {
	const char *original;
	const char *alias;
};

struct ucrt_wrapper {
	void *address;
	enum typenum {
		PLT_OPEN, PLT_READ, PLT_WRITE, PLT_CLOSE,
		PLT_LSEEK, PLT_STAT64, PLT_MALLOC, PLT_FREE,
		PLT_MEMCPY, PLT_MEMSET, PLT_STRLEN, PLT_STRCPY,
		PLT_UNKNOWN
	} type;

	union {
		int (__cdecl*open)(const char *, int, int);
		int (__cdecl*read)(int, void *, unsigned int);
		int (__cdecl*write)(int, const void *, unsigned int);
		int (__cdecl*close)(int);
		long (__cdecl*lseek)(int, long, int);
		int (__cdecl*stat64)(const char *, void *);
		void * (__cdecl*malloc)(size_t);
		void (__cdecl*free)(void *);
		void * (__cdecl*memcpy)(void *, const void *, size_t);
		void * (__cdecl*memset)(void *, int, size_t);
		size_t (__cdecl*strlen)(const char *);
		char * (__cdecl*strcpy)(char *, const char *);
	};
};

struct ucrt_function {
	const char *name;
	ucrt_wrapper::typenum type;
};

//struct trapframe_t {
//	uintptr_t rip;
//	uintptr_t rsp;
//};

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
