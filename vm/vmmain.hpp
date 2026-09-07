#ifndef VMMAIN_HPP
#define VMMAIN_HPP
#include <windows.h>
#include <stdint.h>
#include <setjmp.h>

#include "vmcommon.hpp"







VOID NATIVE_CALL csr_trap (
		_In_ const UINT8 index,
		_In_ const INT32 epc, 
		_in_ const INT32 cause, 
		_in_ const INT32 stat, 
		_in_ const INT32 tval, 
		_in_ const INT32 halt) 
{
	g_vmcs->t_hardware [index].csr.epc 		= (UINT_PTR)epc;			
	g_vmcs->t_hardware [index].csr.cause 	= cause;                 	
	g_vmcs->t_hardware [index].csr.status 	= stat;                 	
	g_vmcs->t_hardware [index].csr.tval 	= tval;                    
	g_vmcs->t_context  [index].halt 		= halt;                    

	raise_exception (RVM_TRAP_EXCEPTION, 0, 0, nullptr); 	
}




#endif
#endif //VMMAIN_HPP
