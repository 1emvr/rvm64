#ifndef VMCS_H
#define VMCS_H
#include <windows.h>
#include <stdint.h>
#include <setjmp.h>

#include "vmcommon.hpp"

#define NATIVE_CALL   	//__attribute__((section(".text$B")))
#define VM_CALL   		//__attribute__((section(".text$B"))) __attribute__((calling_convention("custom")))
#define VM_RDATA    	__attribute__((section(".rdata")))
#define DATA_SCN     	__attribute__((section(".data")))

#define NtCurrentProcess()      ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread()       ((HANDLE)(LONG_PTR)-2)

#define RVM_TRAP_EXCEPTION      0xE0424242
#define DEFAULT_PROC_SIZE     	0x10000
#define INTERNAL_MAGIC1         0x524d5636345f4949ULL  // "RMV64_II"
#define INTERNAL_MAGIC2         0x5f424541434f4e00ULL  // "_BEACON"
#define VM_BEACON_VER           1

#define EXPONENT_MASK           0x7FF0000000000000ULL
#define FRACTION_MASK           0x000FFFFFFFFFFFFFULL
#define RV64_RET                0x00008067


// Safe MIN/MAX that work on both compilers
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


struct {
	INTEL 	HostContext;
	INTEL 	VmContext;

	jmp_buf TrapHandler;
	jmp_buf ExitHandler;

	HANDLE 	InterHandle;
	HANDLE 	MutexRW;

	UINT64 	LoadRsvAddr;
	UINT64 	LoadRsvValid;
							   
	INT 	Trap;
	INT 	Halt;
} VM_CONTEXT;


typedef struct {
    UINT64 Magic1, Magic2;
	UINT64 Self;
	UINT64 Pid;
	UINT64 Tid;

	VM_CONTEXT* Context;

	struct {
		HMODULE Ucrtbase;
		HMODULE Kernel32;
	} Module;

	struct {
		UINT_PTR Epc;
		UINT_PTR Cause;
		UINT_PTR Status;
		UINT_PTR Tval;
	} Csr;

	typedef {
		UINT64 Pc;
		UINT64 Scratch 	[8];
		UINT64 Regs 	[32];
		UINT64 Stack 	[32];
	} Hdw;

	struct {
		UINT64 			Memory;
		UINT64 			MemorySize;
		UINT64			ImageBase;
		volatile UINT64 Ready;   
	} Proc;
} VMCS;


DATA_SCN const UINT_PTR DispatchTable [256] = {
#define ENCRYPT (op) EncryptPtr ((UINT_PTR)(op), (UINT_PTR)0)
    // ITYPE
    ENCRYPT (_ADDI), 		ENCRYPT (_SLTI),
    ENCRYPT (_SLTIU), 		ENCRYPT (_XORI),
    ENCRYPT (_ORI), 		ENCRYPT (_ANDI),
    ENCRYPT (_SLLI), 		ENCRYPT (_SRLI),
    ENCRYPT (_SRAI), 		ENCRYPT (_ADDIW),
    ENCRYPT (_SLLIW), 		ENCRYPT (_SRLIW),
    ENCRYPT (_SRAIW), 		ENCRYPT (_LB),
    ENCRYPT (_LH), 			ENCRYPT (_LW),
    ENCRYPT (_LBU), 		ENCRYPT (_LHU),
    ENCRYPT (_LWU), 		ENCRYPT (_LD),
    ENCRYPT (_FLQ), 		ENCRYPT (_FENCE),
    ENCRYPT (_FENCE_I), 	ENCRYPT (_JALR),
    ENCRYPT (_ECALL), 		ENCRYPT (_EBREAK),
    ENCRYPT (_CSRRW), 		ENCRYPT (_CSRRS),
    ENCRYPT (_CSRRC), 		ENCRYPT (_CSRRWI),
    ENCRYPT (_CSRRSI), 		ENCRYPT (_CSRRCI),
    ENCRYPT (_FCLASS_D), 	ENCRYPT (_LRW),
    ENCRYPT (_LRD), 		ENCRYPT (_FMV_D_X),
    ENCRYPT (_FCVT_S_D), 	ENCRYPT (_FCVT_D_S),
    ENCRYPT (_FCVT_W_D), 	ENCRYPT (_FCVT_WU_D),
    ENCRYPT (_FCVT_D_W), 	ENCRYPT (_FCVT_D_WU),

    // RTYPE
    ENCRYPT (_FADD_D), 		ENCRYPT (_FSUB_D),
    ENCRYPT (_FMUL_D), 		ENCRYPT (_FDIV_D),
    ENCRYPT (_FSGNJ_D), 	ENCRYPT (_FSGNJN_D),
    ENCRYPT (_FSGNJX_D), 	ENCRYPT (_FMIN_D),
    ENCRYPT (_FMAX_D), 		ENCRYPT (_FEQ_D),
    ENCRYPT (_AMOADD_W), 	ENCRYPT (_AMOXOR_W),
    ENCRYPT (_AMOMINU_W), 	ENCRYPT (_AMOMAXU_W),
    ENCRYPT (_SCD), 		ENCRYPT (_AMOSWAP_D),
    ENCRYPT (_AMOADD_D), 	ENCRYPT (_AMOXOR_D),
    ENCRYPT (_AMOAND_D), 	ENCRYPT (_AMOOR_D),
    ENCRYPT (_AMOMIN_D), 	ENCRYPT (_AMOMAX_D),
    ENCRYPT (_AMOMINU_D), 	ENCRYPT (_AMOMAXU_D),
    ENCRYPT (_ADDW), 		ENCRYPT (_SUBW),
    ENCRYPT (_MULW), 		ENCRYPT (_SRLW),
    ENCRYPT (_SRAW), 		ENCRYPT (_DIVUW),
    ENCRYPT (_SLLW), 		ENCRYPT (_DIVW),
    ENCRYPT (_REMW), 		ENCRYPT (_REMUW),
    ENCRYPT (_ADD), 		ENCRYPT (_SUB),
    ENCRYPT (_MUL), 		ENCRYPT (_SLL),
    ENCRYPT (_MULH), 		ENCRYPT (_SLT),
    ENCRYPT (_MULHSU), 		ENCRYPT (_SLTU),
    ENCRYPT (_MULHU), 		ENCRYPT (_XOR),
    ENCRYPT (_DIV), 		ENCRYPT (_SRL),
    ENCRYPT (_SRA), 		ENCRYPT (_DIVU),
    ENCRYPT (_OR), 			ENCRYPT (_REM),
    ENCRYPT (_AND), 		ENCRYPT (_REMU),

    // STYPE
    ENCRYPT (_SB), 			ENCRYPT (_SH),
    ENCRYPT (_SW), 			ENCRYPT (_SD),
    ENCRYPT (_FSW), 		ENCRYPT (_FSD),

    // BTYPE
    ENCRYPT (_BEQ), 		ENCRYPT (_BNE),
    ENCRYPT (_BLT), 		ENCRYPT (_BGE),
    ENCRYPT (_BLTU), 		ENCRYPT (_BGEU),

    // UTYPE/JTYPE
    ENCRYPT (_LUI), 		ENCRYPT (_AUIPC),
    ENCRYPT (_JAL)
#undef ENCRYPT


VM_CALL VOID SetCsrTrap (
		_In_ const INT32 Epc, 
		_In_ const INT32 Cause, 
		_In_ const INT32 Stat, 
		_In_ const INT32 Tval, 
		_In_ const INT32 Halt) 
{
    Vmcs->Csr->Epc 		= (UINT_PTR)Epc;			
    Vmcs->Csr->Cause 	= Cause;                 	
    Vmcs->Csr->Status 	= Stat;                 	
    Vmcs->Csr->Tval 	= Tval;                    
    Vmcs->Context->Halt = Halt;                    

    RaiseException (RVM_TRAP_EXCEPTION, 0, 0, nullptr); 	
}


#ifdef __cplusplus
extern "C" {
#endif
	VOID SaveHostRegCtx ();
	VOID LoadHostRegCtx ();
	VOID SaveVmRegCtx ();
	VOID LoadVmRegCtx ();

	DATA_SCN VMCS* Vmcs = 0;
#ifdef __cplusplus
}
#endif
#endif //VMCS_H
