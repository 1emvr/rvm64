#ifndef VMCS_H
#define VMCS_H
#include <windows.h>
#include <stdint.h>
#include <setjmp.h>

#include "vmcommon.hpp"


enum Screnum {
    Rd = 0, rs1, rs2, rs3, imm,
};

enum Regenum {
    zr = 0, ra, sp, gp, tp,
    T0, T1, T2, S0, S1,
    A0, A1, A2, A3, A4, A5, A6, A7,
    S2, S3, S4, S5, S6, S7, S8, S9, S10, S11,
    T3, T4, T5, T6,
};

enum Typenum {
    Rtype = 1, R4type, Itype, Stype, Btype, Utype, Jtype,
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

typedef struct {
	UINT8 mask;
	Typenum type;
} OPCODE;

VM_DATA OPCODE Encoding [] = {
	{0b1010011, Rtype}, {0b1000011, Rtype}, {0b0110011, Rtype}, {0b1000111, R4type}, {0b1001011, R4type}, {0b1001111, R4type},
	{0b0000011, Itype}, {0b0001111, Itype}, {0b1100111, Itype}, {0b0010011, Itype}, {0b1110011, Itype}, {0b0011011, Itype},
	{0b0100011, Stype}, {0b0100111, Stype}, {0b1100011, Btype}, {0b0010111, Utype}, {0b0110111, Utype}, {0b1101111, Jtype},
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

#include "vmport.hpp"

#ifdef __cplusplus
extern "C" {
#endif
	extern const UINT_PTR dispatch_table [256];

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
