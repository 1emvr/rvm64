#ifndef VMCS_H
#define VMCS_H
#include <windows.h>
#include <stdint.h>
#include <setjmp.h>

#include "vmcommon.hpp"

#define NATIVE_CALL   	//__attribute__((section(".text$B"))) __stdcall
#define VM_CALL   		//__attribute__((section(".text$B"))) __attribute__((calling_convention("custom")))
#define RDATA_SCN    	__attribute__((section(".rdata")))
#define DATA_SCN     	__attribute__((section(".data")))

#define NtCurrentProcess ()      ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread ()       ((HANDLE)(LONG_PTR)-2)

#define RVM_TRAP_EXCEPTION      0xE0424242
#define ARENA_SIZE     			0x10000
#define INTERNAL_MAGIC1         0x524d5636345f4949ULL  // "RMV64_II"
#define INTERNAL_MAGIC2         0x5f424541434f4e00ULL  // "_BEACON"
#define VM_BEACON_VER           1

#define EXPONENT_MASK           0x7FF0000000000000ULL
#define FRACTION_MASK           0x000FFFFFFFFFFFFFULL
#define RV64_RET                0x00008067

#define SINGLE_EXEC 			0xaaaaaaaa
#define INFINITE_EXEC 			0xbbbbbbbb


#define PROCESS_MEMORY_IN_BOUNDS (addr)  								\
	((addr) >= 	(UINT_PTR)(Vmcs->Proc.Memory) && 						\
	 (addr) < 	(UINT_PTR)(Vmcs->Proc.Memory + Vmcs->Proc.MemorySize))


#define STACK_MEMORY_IN_BOUNDS (addr) 									\
	((addr) >= (uintptr_t)vmcs->hdw->vstack && 							\
	 (addr) < (uintptr_t)(vmcs->hdw->vstack + VSTACK_MAX_CAPACITY))



#define MIN (a, b) ([] (auto _a, auto _b) { return _a < _b ? _a : _b; } ((a),(b)))
#define MAX (a, b) ([] (auto _a, auto _b) { return _a > _b ? _a : _b; } ((a),(b)))


enum Screnum {
    RD = 0, RS1, RS2, RS3, IMM,
};


enum Regenum {
    ZR = 0, RA, SP, GP, TP,
    T0, T1, T2, S0, S1,
    A0, A1, A2, A3, A4, A5, A6, A7,
    S2, S3, S4, S5, S6, S7, S8, S9, S10, S11,
    T3, T4, T5, T6,
};


enum Typenum {
    RTYPE = 1, R4TYPE, ITYPE, STYPE, BTYPE, UTYPE, JTYPE,
};


enum RiscvIndex : UINT8 {
	// ITYPE
	_ADDI, _SLTI, _SLTIU, _XORI,
	_ORI, _ANDI, _SLLI, _SRLI,
	_SRAI, _ADDIW, _SLLIW, _SRLIW,
	_SRAIW, _LB, _LH, _LW,
	_LBU, _LHU, _LWU, _LD,
	_FLQ, _FENCE, _FENCE_I, _JALR,
	_ECALL, _EBREAK, _CSRRW, _CSRRS,
	_CSRRC, _CSRRWI, _CSRRSI, _CSRRCI,
	_FCLASS_D, _LRW, _LRD, _FMV_D_X,
	_FCVT_S_D, _FCVT_D_S, _FCVT_W_D, _FCVT_WU_D,
	_FCVT_D_W, _FCVT_D_WU,

	// RTYPE
	_FADD_D, _FSUB_D, _FMUL_D, _FDIV_D,
	_FSGNJ_D, _FSGNJN_D, _FSGNJX_D,
	_FMIN_D, _FMAX_D, _FEQ_D, _FLT_D,
	_FLE_D, _SCW, _AMOSWAP_W, _AMOADD_W,
	_AMOXOR_W, _AMOAND_W, _AMOOR_W, _AMOMIN_W,
	_AMOMAX_W, _AMOMINU_W, _AMOMAXU_W,
	_SCD, _AMOSWAP_D, _AMOADD_D,
	_AMOXOR_D, _AMOAND_D, _AMOOR_D, _AMOMIN_D,
	_AMOMAX_D, _AMOMINU_D, _AMOMAXU_D,
	_ADDW, _SUBW, _MULW, _SRLW,
	_SRAW, _DIVUW, _SLLW, _DIVW,
	_REMW, _REMUW, _ADD, _SUB,
	_MUL, _SLL, _MULH, _SLT,
	_MULHSU, _SLTU, _MULHU, _XOR,
	_DIV, _SRL, _SRA, _DIVU,
	_OR, _REM, _AND, _REMU,

	// STYPE
	_SB, _SH, _SW, _SD,E
	_FSW, _FSD,

	// BTYPE
	_BEQ, _BNE, _BLT, _BGE,
	_BLTU, _BGEU,

	// UTYPE/JTYPE
	_LUI, _AUIPC, _JAL
};


enum Causenum {
    SupervSoftwareInter 	= 0xb11,
    MachineSoftwareInter    = 0xb13,
    SupervTimerInter    	= 0xb15,
    MachineTimerInter       = 0xb17,
    SupervExternalInter 	= 0xb19,
    MachineExternalInter    = 0xb111,
    Reserved1   			= 0xb116,
    InstructionAddressMiss	= 0xb00,
    InstructionAccessFault  = 0xb01,
    InstructionIllegal      = 0xb02,
    Breakpoint              = 0xb03,
    LoadAddressMiss       	= 0xb04,
    LoadAccessFault         = 0xb05,
    StoreAmoAddressMiss  	= 0xb06,
    StoreAmoAccessFault     = 0xb07,
    EnvCallFromUMode  		= 0xb08,
    EnvCallFromSMode  		= 0xb09,
    EnvCallFromMMode  		= 0xb011,
    InstructionPageFault    = 0xb012,
    LoadPageFault           = 0xb013,
    StoreAmoPageFault       = 0xb015,
    Reserved				= 0xb024,
    ImageBadSymbol          = 0xb025,
    ImageBadLoad            = 0xb026,
    ImageBadType            = 0xb027,
    EnvExecute           	= 0xb028,
    OutOfMemory             = 0xb029,
    EnvNative            	= 0xb030,
    EnvShutdown             = 0xb031,
	EnvInter				= 0xb032,
    InvalidChannel          = 0xffff,
};


typedef struct {
	UINT8 mask;
	Typenum type;
} OPCODE;


typedef struct { 
    UINT64 Rip, Rsp, Rax, Rbx, Rsi, Rdi, Rbp;
    UINT64 R12, R13, R14, R15;
    UINT64 Rflags;
} CPU_CONTEXT;


typedef struct {
	HANDLE 		Handle;
	DWORD 		Pid;
	UINT_PTR 	Address;
	SIZE_T 		Size;
} WIN_PROC;


struct {
	CPU_CONTEXT host_context;
	CPU_CONTEXT vm_context;

	jmp_buf interrupt;
	jmp_buf branch;
	jmp_buf shutdown;

	HANDLE 	h_interupt;
	HANDLE 	mutex_rw;

	UINT64 	load_rsv_addr;
	UINT64 	load_rsv_valid;
							   
	volatile int halt;
} VM_CONTEXT;


typedef struct {
	UINT64 elf_off;
	UINT64 param_off;

	UINT64 packed_sz;
	UINT64 runtime_sz;
} ElfEntry;


struct THREAD_ARGS {
	LPVOID elf_base;
	LPVOID param_base;
};


typedef struct {
	UINT8 		*data;
	UINT64 		capacity;
	UINT64 		used;
	ElfEntry 	*entries;
	SIZE_T 		count;
} ARENA;


#define MAX_VM_THREADS 5
typedef struct {
    UINT64 magic1, magic2;
	UINT64 self;
	UINT64 pid;
	UINT64 tid;

	UINT64 pc;
	UINT64 scratch 	[8];
	UINT64 regs 	[32];
	UINT64 stack 	[32];

	struct {
		UINT_PTR epc;
		UINT_PTR cause;	
		UINT_PTR status;
		UINT_PTR tval;
	} csr;
} THREAD_HDW;


typedef struct {
	ARENA 		*code_arena;
	ARENA 		*heap_arena;

	struct {
		HMODULE ucrtbase;
		HMODULE kernel32;
	} modules;

	HANDLE 		one_time_thread 	[MAX_VM_THREADS];		
	HANDLE 		infinite_thread 	[MAX_VM_THREADS];		

	HANDLE 		t_type 		[MAX_VM_THREADS];		
	VM_CONTEXT 	t_context 	[MAX_VM_THREADS]; 
	UINT64 		t_count;

	THREAD_ARGS t_args 		[MAX_VM_THREADS];
	THREAD_HDW 	t_hardware 	[MAX_VM_THREADS];
} VMCS;


#ifdef __cplusplus
extern "C" {
#endif
	VOID save_registers (CPU_CONTEXT* context);
	VOID load_registers (CPU_CONTEXT* context);

	DATA_SCN VMCS* g_vmcs = 0;

#ifdef __cplusplus
}
#endif


VOID NATIVE_CALL csr_trap (
		_In_ const UINT8 machine_index,
		_In_ const INT32 epc, 
		_in_ const int32 cause, 
		_in_ const int32 stat, 
		_in_ const int32 tval, 
		_in_ const int32 halt) 
{
    g_vmcs->t_hardware [machine_index].csr.epc 		= (UINT_PTR)epc;			
    g_vmcs->t_hardware [machine_index].csr.cause 	= cause;                 	
    g_vmcs->t_hardware [machine_index].csr.status 	= stat;                 	
    g_vmcs->t_hardware [machine_index].csr.tval 	= tval;                    
    g_vmcs->t_context  [machine_index].halt 		= halt;                    

    RaiseException (RVM_TRAP_EXCEPTION, 0, 0, nullptr); 	
}


NATIVE_CALL BOOL is_elf (_In_ const UINT8 *base) {
	return 	base [EI_MAG0] == ELFMAG0 && base [EI_MAG1] == ELFMAG1 && 
			base [EI_MAG2] == ELFMAG2 && base [EI_MAG3] == ELFMAG3;
}


NATIVE_CALL UINT64 elf_runtime_size (
		_In_ const 	UINT8  	*base, 
		_Inout_ 	UINT64 	*out_align)
{
	const ELF64_EHDR *ehdr = (const ELF64_EHDR*)base;
	const ELF64_PHDR *phdr = (const ELF64_PHDR*)(base + ehdr->e_phoff);

	UINT64 lo = (UINT64)-1, hi = 0, align = 0x1000;

	for (UINT8 prog_index = 0; prog_index < ehdr->e_phnum; prog_index++) {
		if (phdr [prog_index].p_type != PT_LOAD) {
			continue;
		}

		UINT64 seg_lo 	= phdr [prog_index].p_vaddr;
		UINT64 seg_hi 	= phdr [prog_index].p_vaddr + phdr [prog_index].p_memsz;
		UINT64 p_align 	= phdr [prog_index].p_align;

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

		for (UINT8 prog_index = 0; prog_index < ehdr->e_phnum; prog_index++) {
			const UINT64 end = phdr [prog_index].ph_offset + phdr [prog_index].p_filesz;
			if (end > max) max = end;
		}
	}
	if (ehdr->e_shoff) {
		const UINT64 end = ehdr->e_shoff + (UINT64)(ehdr->e_shnum * ehdr->e_shentsize);
		if (end > max) max = end;

		const ELF64_SHDR *shdr = (const ELF64_SHDR *)base + ehdr->e_shoff;

		for (UINT8 seg_index = 0; seg_index < ehdr->e_shnum; seg_index++) {
			if (shdr [seg_index].sh_type == SHT_NOBITS) {
				continue;
			}

			const UINT64 real_end = shdr [seg_index].sh_offset + shdr [seg_index].sh_size;
			if (real_end > max) max = real_end;
		}
	}
	return max;
}


// Idea to create 2 arenas: one for program code, the other for heap + create a pseudo-allocator/memory manager (512MB blocks ?)
// The arena allocators will be the primary source for memory, then malloc will resolve to a custom allocator.

BOOL NATIVE_CALL calculate_runtime_size () {
	UINT8 *cursor 		= g_vmcs->code_arena->data;
	ElfEntry *entries 	= g_vmcs->code_arena->entries;

	UINT64 offset 		= 0;
	UINT64 n_threads 	= (UINT64)cursor [0]; 

#define update_arena (b, o, sz) \
	b += sz;					\
	o += sz;					

	update_arena (cursor, offset, sizeof (UINT64)); 
	if (n_threads == 0 || n_threads > MAX_VM_THREADS) {
		return false;
	}

	for (UINT8 thread_index = 0; thread_index < n_threads; thread_index++) {  
		// TODO: determine types of threads (here or during relocation)
		UINT64 param_sz = cursor [0]; 

		update_arena (cursor, offset, sizeof (UINT64) + param_sz);
		if (!is_elf (cursor) || cursor [EI_CLASS] != ELFCLASS64) {
			return false; 
		}

		entries [thread_index].runtime_sz 	= elf_runtime_size (cursor, nullptr);
		entries [thread_index].packed_sz 	= elf_image_size (cursor);

		update_arena (cursor, offset, entries [thread_index].packed_sz);
	}

	UINT64 total = 0;

	for (UINT8 thread_index = 0; thread_index < n_threads; thread_index++) {
		total += entries [thread_index].runtime_sz;
	}
	if (total > g_vmcs->code_arena->capacity) {
		ARENA *new_a = arena_realloc (g_vmcs->code_arena, total);

		g_vmcs->code_arena = new_a;
		cursor = offset; // unnecessary ??	
	}

	return true;
}


VOID NATIVE_CALL thread_main (_In_ const LPVOID parameters) {
	ThreadArgs *args = (ThreadArgs *)parameters;
		// this is where the machine code FDX cycle will take place
	return;
}


BOOL NATIVE_CALL start_thread (
		_Out_ 		HANDLE* 				handle,
		_In_ const 	LPTHREAD_START_ROUTINE	call,
		_In_ const 	LPVOID 					args) 
{
	*handle = CreateThread (nullptr, 0, call, args, 0, nullptr); 

	if (*handle == nullptr) {
		return false;
	}
	return true;
}


VOID NATIVE_CALL rvm64_main (
		_In_ const UINT_PTR data, 
		_In_ const UINT_PTR data_sz) 
{
	ARENA *a = g_vmcs->arena;

	UINT_PTR data 		= a->data;
	ElfEntry *entries 	= a->entries;

	if (!calculate_runtime_size ()) {
		goto defer;
	}
	if (a->count == 0 || a->count > MAX_VM_THREADS) {
		goto defer;
	}
	/* 
	if (!relocate_runtime_memory ()) { // should either move infinite threads to their own memory or memory manager should keep tabs on everything
		goto defer;
	}
	 */ 
	
	for (UINT8 thread_index = 0; thread_index < a->count; thread_index++) {
		UINT_PTR elf_base 	= data + entires [thread_index].elf_off;
		UINT_PTR param_base = data + entries [thread_index].param_off;

		if (param_base [0] == 0) param_base = nullptr;

		g_vmcs->t_args [thread_index].elf_base 		= elf_base;
		g_vmcs->t_args [thread_index].param_base 	= param_base;

		UINT64 type 		= g_vmcs->t_type [thread_index];
		THREAD_ARGS *args 	= &g_vmcs->t_args [thread_index];

		if (type == SINGLE EXEC) {
			if (!start_thread (&g_vmcs->one_time_thread [thread_index], (LPTHREAD_START_ROUTINE)thread_main, (LPVOID)args)) {
				a->count -= 1;
			}
		} else if (type == INFINITE_EXEC) {
			if (!start_thread (&g_vmcs->infinite_thread [thread_index], (LPTHREAD_START_ROUTINE)thread_main, (LPVOID)args)) { // how do we access these infinite threads?
				a->count -= 1;
			}
		} else {
			return;
			// error
		}
	}

	DWORD result = WaitForMultipleObjects ((DWORD)a->count, g_vmcs->one_time_thread, true, INFINITE); 

	for (HANDLE handle_index = 0; handle_index < a->count; handle_index++) {
		if (g_vmcs->one_time_thread [handle_index]) {

			CloseHandle (threads [handle_index]);
			HeapFree (threads [handle_index]);
		}
	}
	// post_thread_response () ??
defer:
	return;
}


VOID NATIVE_CALL rvm64_start (
		_In_ const UINT_PTR* data,
		_In_ const UINT_PTR* data_sz) 
{
	VMCS instance = { };
	g_vmcs = &instance; // a global vmcs instance to track everything (?)

	rvm64_main (data, data_sz); // TODO: arena_allocate () 
}
#endif
#endif //VMCS_H
