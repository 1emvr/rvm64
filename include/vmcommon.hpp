#ifndef _VMCOMMON_H
#define _VMCOMMON_H

#include <windows.h>
#include "vmport.hpp"   

#if defined(_MSC_VER)
    #define _native
    #define _vmcall
    #define _naked    __declspec(naked)
    #define _export   __declspec(dllexport)
    #define _rdata
    #define _data
    #define _noinline __declspec(noinline)
    #define _align64  __declspec(align(64))
    #define _externc  extern "C"
    #define __typeof__(x) decltype(x)
#else
    #define _native   //__attribute__((section(".text$B")))
    #define _vmcall   //__attribute__((section(".text$B"))) __attribute__((calling_convention("custom")))
    #define _naked    __attribute__((naked))
    #define _export   __attribute__((visibility("default")))
    #define _rdata    __attribute__((section(".rdata")))
    #define _data     __attribute__((section(".data")))
    #define _noinline __attribute__((noinline))
    #define _align64  __attribute__((packed, aligned(64)))
    #define _externc  extern "C"
#endif

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

enum causenum {
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


#endif // _VMCOMMON_H
