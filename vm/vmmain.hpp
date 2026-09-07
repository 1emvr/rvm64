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
	_SB, _SH, _SW, _SD,
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
	LPVOID img_base;
	LPVOID param_base;
};


typedef struct {
	UINT8 		*data;
	UINT8		*offset;
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

	struct {
		HMODULE ucrtbase;
		HMODULE kernel32;
	} modules;

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
	ARENA 		*arena;
	HANDLE 		h_thread 	[MAX_VM_THREADS];		
	UINT64 		h_count;

	VM_CONTEXT 	context 	[MAX_VM_THREADS]; 
	THREAD_HDW 	thread_hdw 	[MAX_VM_THREADS];
	THREAD_ARGS thread_args [MAX_VM_THREADS];
} VMCS;


#ifdef __cplusplus
extern "C" {
#endif
	VOID save_registers (CPU_CONTEXT* context);
	VOID load_registers (CPU_CONTEXT* context);

	DATA_SCN VMCS* g_vmcs = 0;

#ifdef __cplusplus
}


VM_CALL VOID SetCsrTrap (
		_In_ const INT32 epc, 
		_in_ const int32 cause, 
		_in_ const int32 stat, 
		_in_ const int32 tval, 
		_in_ const int32 halt) 
{
    g_vmcs->csr->epc 		= (UINT_PTR)epc;			
    g_vmcs->csr->cause 		= cause;                 	
    g_vmcs->csr->status 	= stat;                 	
    g_vmcs->csr->tval 		= tval;                    
    g_vmcs->context->halt 	= halt;                    

    RaiseException (RVM_TRAP_EXCEPTION, 0, 0, nullptr); 	
}


NATIVE_CALL BOOL is_elf (_In_ const UINT8 *base) {
	return base [EI_MAG0] == ELFMAG0 && base [EI_MAG1] == ELFMAG1 && 
			base [EI_MAG2] == ELFMAG2 && base [EI_MAG3] == ELFMAG3;
}


NATIVE_CALL UINT64 elf_runtime_size (
		_In_ const 	UINT8  	*base, 
		_Inout_ 	UINT64 	*out_align)
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


VOID NATIVE_CALL rvm64_main () {
	if (!process_packets (a)) 		goto defer;

	if (a->count == 0) 				goto defer;
	if (a->count > MAX_VM_THREADS) 	goto defer;

	ARENA *a = g_vmcs->arena;

	for (SIZE_T i = 0; i < a->count; i++) {
		g_vmcs->thread_args [i].img_base 	= a->data + a->entires [i].elf_off;
		g_vmcs->thread_args [i].param_base 	= a->data + a->entries [i].param_offset;

		if (param_base [0] == 0) param_base = nullptr;

		g_vmcs->threads [i] = CreateThread (
				nullptr, 0, (LPTHREAD_START_ROUTINE)vm_thread, 
				&g_vmcs->thread_args [i], 0, nullptr); 
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
#endif
#endif //VMCS_H
