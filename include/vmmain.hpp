#ifndef VMCS_H
#define VMCS_H
#include <windows.h>
#include <stdint.h>
#include <setjmp.h>

#include "vmcommon.hpp"

#define NATIVE_CALL   	//__attribute__((section(".text$B")))
#define VM_CALL   		//__attribute__((section(".text$B"))) __attribute__((calling_convention("custom")))
#define NAKED    		__attribute__((naked))
#define EXPORT   		__attribute__((visibility("default")))
#define VM_RDATA    	__attribute__((section(".rdata")))
#define VM_DATA     	__attribute__((section(".data")))

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
	_rv_addi, _rv_slti, _rv_sltiu, _rv_xori,
	_rv_ori, _rv_andi, _rv_slli, _rv_srli,
	_rv_srai, _rv_addiw, _rv_slliw, _rv_srliw,
	_rv_sraiw, _rv_lb, _rv_lh, _rv_lw,
	_rv_lbu, _rv_lhu, _rv_lwu, _rv_ld,
	_rv_flq, _rv_fence, _rv_fence_i, _rv_jalr,
	_rv_ecall, _rv_ebreak, _rv_csrrw, _rv_csrrs,
	_rv_csrrc, _rv_csrrwi, _rv_csrrsi, _rv_csrrci,
	_rv_fclass_d, _rv_lrw, _rv_lrd, _rv_fmv_d_x,
	_rv_fcvt_s_d, _rv_fcvt_d_s, _rv_fcvt_w_d, _rv_fcvt_wu_d,
	_rv_fcvt_d_w, _rv_fcvt_d_wu,

	// RTYPE
	_rv_fadd_d, _rv_fsub_d, _rv_fmul_d, _rv_fdiv_d,
	_rv_fsgnj_d, _rv_fsgnjn_d, _rv_fsgnjx_d,
	_rv_fmin_d, _rv_fmax_d, _rv_feq_d, _rv_flt_d,
	_rv_fle_d, _rv_scw, _rv_amoswap_w, _rv_amoadd_w,
	_rv_amoxor_w, _rv_amoand_w, _rv_amoor_w, _rv_amomin_w,
	_rv_amomax_w, _rv_amominu_w, _rv_amomaxu_w,
	_rv_scd, _rv_amoswap_d, _rv_amoadd_d,
	_rv_amoxor_d, _rv_amoand_d, _rv_amoor_d, _rv_amomin_d,
	_rv_amomax_d, _rv_amominu_d, _rv_amomaxu_d,
	_rv_addw, _rv_subw, _rv_mulw, _rv_srlw,
	_rv_sraw, _rv_divuw, _rv_sllw, _rv_divw,
	_rv_remw, _rv_remuw, _rv_add, _rv_sub,
	_rv_mul, _rv_sll, _rv_mulh, _rv_slt,
	_rv_mulhsu, _rv_sltu, _rv_mulhu, _rv_xor,
	_rv_div, _rv_srl, _rv_sra, _rv_divu,
	_rv_or, _rv_rem, _rv_and, _rv_remu,

	// STYPE
	_rv_sb, _rv_sh, _rv_sw, _rv_sd,
	_rv_fsw, _rv_fsd,

	// BTYPE
	_rv_beq, _rv_bne, _rv_blt, _rv_bge,
	_rv_bltu, _rv_bgeu,

	// UTYPE/JTYPE
	_rv_lui, _rv_auipc, _rv_jal
};


#define NtCurrentProcess()      ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread()       ((HANDLE)(LONG_PTR)-2)

#define VSTACK_MAX_CAPACITY     (sizeof(uint64_t) * 32)
#define RVM_TRAP_EXCEPTION      0xE0424242

#define PROCESS_BUFFER_SIZE     0x10000
#define VM_MAGIC1               0x524d5636345f4949ULL  // "RMV64_II"
#define VM_MAGIC2               0x5f424541434f4e00ULL  // "_BEACON"
#define VM_BEACON_VER           1

#define EXPONENT_MASK           0x7FF0000000000000ULL
#define FRACTION_MASK           0x000FFFFFFFFFFFFFULL
#define RV64_RET                0x00008067

#define CSR_SET_TRAP(epc, cause, stat, val, hlt) 		\
    vmcs->hdw->csr.m_epc = (uintptr_t)(epc);          	\
    vmcs->hdw->csr.m_cause = (cause);                 	\
    vmcs->hdw->csr.m_status = (stat);                 	\
    vmcs->hdw->csr.m_tval = (val);                    	\
    vmcs->halt = (hlt);                          		\
    RaiseException(RVM_TRAP_EXCEPTION, 0, 0, nullptr); 	\
    VM_UNREACHABLE()

// Safe MIN/MAX that work on both compilers
#define MIN(a, b) ([](auto _a, auto _b){ return _a < _b ? _a : _b; }((a),(b)))
#define MAX(a, b) ([](auto _a, auto _b){ return _a > _b ? _a : _b; }((a),(b)))

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
    NativeCall       		= 0xb024,
    ImageBadSymbol          = 0xb025,
    ImageBadLoad            = 0xb026,
    ImageBadType            = 0xb027,
    EnvExecute           	= 0xb028,
    OutOfMemory             = 0xb029,
    EnvBranch            	= 0xb030,
    EnvExit              	= 0xb031,
    InvalidChannel          = 0xffff,
};


typedef struct {
	UINT8 mask;
	Typenum type;
} OPCODE;


VM_DATA OPCODE Encoding [] = {
	{0b1010011, RTYPE}, {0b1000011, RTYPE}, {0b0110011, RTYPE}, {0b1000111, R4TYPE}, {0b1001011, R4TYPE}, {0b1001111, R4TYPE},
	{0b0000011, ITYPE}, {0b0001111, ITYPE}, {0b1100111, ITYPE}, {0b0010011, ITYPE}, {0b1110011, ITYPE}, {0b0011011, ITYPE},
	{0b0100011, STYPE}, {0b0100111, STYPE}, {0b1100011, BTYPE}, {0b0010111, UTYPE}, {0b0110111, UTYPE}, {0b1101111, JTYPE},
};



typedef struct {
    UINT64 Rip, Rsp, Rax, Rbx, Rcx, Rdx, Rsi, Rdi, Rbp;
    UINT64 R8, R9, R10, R11, R12, R13, R14, R15;
    UINT64 Rflags;
} INTEL;

typedef struct {
	HANDLE 		Handle;
	DWORD 		Pid;
	UINT_PTR 	Address;
	SIZE_T 		Size;
} WIN_PROC;

typedef struct _vmcs {
    UINT64 Magic1, Magic2;
	UINT64 PtrSelf;
	UINT64 Pid;
	UINT64 Tid;

	struct {
		UINT_PTR Epc;
		UINT_PTR Cause;
		UINT_PTR Status;
		UINT_PTR Tval;
	} Csr;
	typedef {
		UINT64 Pc;
		UINT64 Scratch [8];
		UINT64 Regs [32];
		UINT64 Stack [32];
	} Gpr;

	jmp_buf TrapHandler;
	jmp_buf ExitHandler;

	struct {
		UINT64 Memory;
		UINT64 MemorySize;
		volatile UINT64 Ready;   
	} VmProc;
							   
	UINT64 LoadRsvAddr;
	UINT64 LoadRsvValid;

	INT Trap;
	INT Halt;
} VMCS;


VM_DATA const UINT_PTR DispatchTable [256] = {
#define ENCRYPT (op) EncryptPtr ((UINT_PTR)(op), (UINT_PTR)0)
    // ITYPE
    ENCRYPT (itype::rv_addi), 		ENCRYPT (itype::rv_slti),
    ENCRYPT (itype::rv_sltiu), 		ENCRYPT (itype::rv_xori),
    ENCRYPT (itype::rv_ori), 		ENCRYPT (itype::rv_andi),
    ENCRYPT (itype::rv_slli), 		ENCRYPT (itype::rv_srli),
    ENCRYPT (itype::rv_srai), 		ENCRYPT (itype::rv_addiw),
    ENCRYPT (itype::rv_slliw), 		ENCRYPT (itype::rv_srliw),
    ENCRYPT (itype::rv_sraiw), 		ENCRYPT (itype::rv_lb),
    ENCRYPT (itype::rv_lh), 		ENCRYPT (itype::rv_lw),
    ENCRYPT (itype::rv_lbu), 		ENCRYPT (itype::rv_lhu),
    ENCRYPT (itype::rv_lwu), 		ENCRYPT (itype::rv_ld),
    ENCRYPT (itype::rv_flq), 		ENCRYPT (itype::rv_fence),
    ENCRYPT (itype::rv_fence_i), 	ENCRYPT (itype::rv_jalr),
    ENCRYPT (itype::rv_ecall), 		ENCRYPT (itype::rv_ebreak),
    ENCRYPT (itype::rv_csrrw), 		ENCRYPT (itype::rv_csrrs),
    ENCRYPT (itype::rv_csrrc), 		ENCRYPT (itype::rv_csrrwi),
    ENCRYPT (itype::rv_csrrsi), 	ENCRYPT (itype::rv_csrrci),
    ENCRYPT (itype::rv_fclass_d), 	ENCRYPT (itype::rv_lrw),
    ENCRYPT (itype::rv_lrd), 		ENCRYPT (itype::rv_fmv_d_x),
    ENCRYPT (itype::rv_fcvt_s_d), 	ENCRYPT (itype::rv_fcvt_d_s),
    ENCRYPT (itype::rv_fcvt_w_d), 	ENCRYPT (itype::rv_fcvt_wu_d),
    ENCRYPT (itype::rv_fcvt_d_w), 	ENCRYPT (itype::rv_fcvt_d_wu),

    // RTYPE
    ENCRYPT (rtype::rv_fadd_d), 	ENCRYPT (rtype::rv_fsub_d),
    ENCRYPT (rtype::rv_fmul_d), 	ENCRYPT (rtype::rv_fdiv_d),
    ENCRYPT (rtype::rv_fsgnj_d), 	ENCRYPT (rtype::rv_fsgnjn_d),
    ENCRYPT (rtype::rv_fsgnjx_d), 	ENCRYPT (rtype::rv_fmin_d),
    ENCRYPT (rtype::rv_fmax_d), 	ENCRYPT (rtype::rv_feq_d),
    ENCRYPT (rtype::rv_flt_d), 		ENCRYPT (rtype::rv_fle_d),
    ENCRYPT (rtype::rv_scw), 		ENCRYPT (rtype::rv_amoswap_w),
    ENCRYPT (rtype::rv_amoadd_w), 	ENCRYPT (rtype::rv_amoxor_w),
    ENCRYPT (rtype::rv_amoand_w), 	ENCRYPT (rtype::rv_amoor_w),
    ENCRYPT (rtype::rv_amomin_w), 	ENCRYPT (rtype::rv_amomax_w),
    ENCRYPT (rtype::rv_amominu_w), 	ENCRYPT (rtype::rv_amomaxu_w),
    ENCRYPT (rtype::rv_scd), 		ENCRYPT (rtype::rv_amoswap_d),
    ENCRYPT (rtype::rv_amoadd_d), 	ENCRYPT (rtype::rv_amoxor_d),
    ENCRYPT (rtype::rv_amoand_d), 	ENCRYPT (rtype::rv_amoor_d),
    ENCRYPT (rtype::rv_amomin_d), 	ENCRYPT (rtype::rv_amomax_d),
    ENCRYPT (rtype::rv_amominu_d), 	ENCRYPT (rtype::rv_amomaxu_d),
    ENCRYPT (rtype::rv_addw), 		ENCRYPT (rtype::rv_subw),
    ENCRYPT (rtype::rv_mulw), 		ENCRYPT (rtype::rv_srlw),
    ENCRYPT (rtype::rv_sraw), 		ENCRYPT (rtype::rv_divuw),
    ENCRYPT (rtype::rv_sllw), 		ENCRYPT (rtype::rv_divw),
    ENCRYPT (rtype::rv_remw), 		ENCRYPT (rtype::rv_remuw),
    ENCRYPT (rtype::rv_add), 		ENCRYPT (rtype::rv_sub),
    ENCRYPT (rtype::rv_mul), 		ENCRYPT (rtype::rv_sll),
    ENCRYPT (rtype::rv_mulh), 		ENCRYPT (rtype::rv_slt),
    ENCRYPT (rtype::rv_mulhsu), 	ENCRYPT (rtype::rv_sltu),
    ENCRYPT (rtype::rv_mulhu), 		ENCRYPT (rtype::rv_xor),
    ENCRYPT (rtype::rv_div), 		ENCRYPT (rtype::rv_srl),
    ENCRYPT (rtype::rv_sra), 		ENCRYPT (rtype::rv_divu),
    ENCRYPT (rtype::rv_or), 		ENCRYPT (rtype::rv_rem),
    ENCRYPT (rtype::rv_and), 		ENCRYPT (rtype::rv_remu),

    // STYPE
    ENCRYPT (stype::rv_sb), 	ENCRYPT (stype::rv_sh),
    ENCRYPT (stype::rv_sw), 	ENCRYPT (stype::rv_sd),
    ENCRYPT (stype::rv_fsw), 	ENCRYPT (stype::rv_fsd),

    // BTYPE
    ENCRYPT (btype::rv_beq), 	ENCRYPT (btype::rv_bne),
    ENCRYPT (btype::rv_blt), 	ENCRYPT (btype::rv_bge),
    ENCRYPT (btype::rv_bltu), 	ENCRYPT (btype::rv_bgeu),

    // UTYPE/JTYPE
    ENCRYPT (utype::rv_lui), ENCRYPT (utype::rv_auipc),
    ENCRYPT (jtype::rv_jal)

#undef ENCRYPT

#include "vmport.hpp"

#ifdef __cplusplus
extern "C" {
#endif
	VOID SaveHostContext ();
	VOID RestoreHostContext ();
	VOID SaveVmContext ();
	VOID RestoreVmContext ();

	VM_DATA VMCS* 	Vmcs 		= 0;
	VM_DATA HANDLE 	VmcsMux 	= 0;
	VM_DATA HANDLE 	VehHandle 	= 0;

	VM_DATA INTEL HostContext 	= { };
	VM_DATA INTEL VmContext 	= { };
#ifdef __cplusplus
}
#endif
#endif //VMCS_H
