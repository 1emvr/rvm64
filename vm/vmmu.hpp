#ifndef VMMU_H
#define VMMU_H
#include "../include/vmmain.hpp"

#define PROT_READ	0x1		
#define PROT_WRITE	0x2		
#define PROT_EXEC	0x4		
#define PROT_SEM	0x8	


LONG CALLBACK InterruptHandler (PEXCEPTION_POINTERS ExceptionInfo) {
	DWORD Code 		= ExceptionInfo->ExceptionRecord->ExceptionCode;
	CONTEXT *WinCtx = ExceptionInfo->ContextRecord;

	Vmcs->Csr.Cause 	= Code;
	Vmcs->Csr.Epc 		= WinCtx->Rip;

	if (Code == STATUS_SINGLE_STEP) {
		return EXCEPTION_CONTINUE_SEARCH;
	}
	if (Code != RVM_TRAP_EXCEPTION) { // NOTE: If we violate something on the host, do we shutdown or halt?
		Vmcs->Context->Halt = 1;
		longjmp (Vmcs->Context->Interrupt, true);
	}

	switch (Vmcs->Csr.Cause) {
		case ENV_SHUTDOWN: 	longjmp (Vmcs->Context->Shutdown, true);
		case ENV_BRANCH: 	longjmp (Vmcs->Context->Interrupt, true);
		case ENV_EXECUTE:
		{
			VOID (WINAPI* Memory) (VOID) = (VOID (WINAPI*) (VOID)) Vmcs->Hdw.Pc;
			Memory ();
			break;
		}
		case ENV_NATIVE: 
		{
			NativeCall ();
			break;
		}
		default: 
			break;
	}

	RegRead (UINT_PTR, Vmcs->Hdw.Pc, RA); 
	longjmp (Vmcs->Context->Interrupt, true); 
}


VM_CALL VOID MemoryInit (
		_Out_ UINT_PTR* Memory, 
		_Out_ UINT_PTR* MemorySize) 
{
	Vmcs->Self 		= (UINT64) Vmcs;
	*MemorySize 	= (UINT64) DEFAULT_PROC_SIZE;
	*Memory 		= (UINT64) VirtualAlloc (nullptr, DEFAULT_PROC_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (! *Memory) {
		SetCsrTrap (Vmcs->Hdw.Pc, GetLastError (), 0, 0, 1);
		return;
	}

	Vmcs->Module.Kernel32 = GetModuleHandle ("kernel32.dll");
	Vmcs->Module.Ucrtbase = GetModuleHandle ("ucrtbase.dll");

	Vmcs->Hdw.Regs [SP] = (UINT_PTR)(Vmcs->Hdw.Stack + sizeof (Vmcs->Hdw.Stack));
}


VM_CALL VOID ContextInit (_Inout_ VM_CONTEXT** Context) {
	if (!Context) {
		return;
	}
	*Context = (VM_CONTEXT*) VirtualAlloc (nullptr, sizeof (VM_CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (! *Context) {
		SetCsrTrap (0, OutOfMemory, 0, 0, 1);
	}

	(*Context)->InterHandle 	= AddVectoredExceptionHandler (1, InterruptHandler);
	(*Context)->Halt 			= 0;
	(*Context)->Ready			= 0;

}


VM_CALL VOID MemoryRelease (
		_In_ const UINT_PTR* Memory, 
		_In_ const UINT_PTR* MemorySize) 
{
	if (*Memory) {
		MemSet (*Memory, 0, *MemorySize);
		VirtualFree ((LPVOID)*Memory, 0, MEM_RELEASE);

		*Memory = 0;
	}

	*MemorySize = 0;
	Vmcs->Context.Ready = 0;

	Vmcs->Magic1 = 0;
	Vmcs->Magic2 = 0;
}


VM_CALL VOID ContextRelease (_In_ VM_CONTEXT** Context) {
	RemoveVectoredExceptionHandler ((*Context)->InterHandle);
	(*Context)->InterHandle = 0;

	VirtualFree (*Context, 0, MEM_RELEASE);
	*Context = 0;
}


VM_CALL VOID SetLoadRsv (
		_In_ const INT 		HartId, 
		_In_ const UINT_PTR Address) 
{
	WaitForSingleObject (Vmcs->Context->RWMutex, INFINITE);

	Vmcs->Context->LoadRsvAddress = Address; // vmcs_array[hart_id]->load_rsv_addr = address;
	Vmcs->Context->LoadRsvValid = true; // vmcs_array[hart_id]->load_rsv_valid = true;

	ReleaseMutex (Vmcs->Context->RWMutex);
}


VM_CALL VOID ClearLoadRsv (_In_ const INT HartId) {
	WaitForSingleObject (Vmcs->Context->RWMutex, INFINITE);

	Vmcs->LoadRsvAddr = 0LL; // vmcs_array[hart_id]->load_rsv_addr = 0LL;
	Vmcs->LoadRsvValid = false; // vmcs_array[hart_id]->load_rsv_valid = false;

	ReleaseMutex (Vmcs->Context->RWMutex);
}


VM_CALL BOOL CheckLoadRsv (
		_In_ const INT 		HartId, 
		_In_ const UINT_PTR Address) 
{
	INT Valid = 0;

	WaitForSingleObject (Vmcs->Context->RWMutex, INFINITE);
	Valid = (Vmcs->Context->LoadRsvValid && Vmcs->Context->LoadRsvAddress == address); 

	ReleaseMutex (Vmcs->Context->RWMutex);
	return Valid;
}


BOOL VmWriteProcessMemory (
		_In_ const 	HANDLE 		Handle, 
		_In_ const 	UINT_PTR 	Address, 
		_In_ const 	UINT8*		Buffer, 
		_In_ const 	SIZE_T 		Length, 
		_Out_ 		SIZE_T*		Write) 
{
	DWORD Oldprot = 0;
	if (! VirtualProtectEx (Handle, (LPVOID)Address, Length, PAGE_EXECUTE_READWRITE, &Oldprot)) {
		return false;
	}

	BOOL Result = WriteProcessMemory (Handle, (LPVOID)Address, Buffer, Length, Write);
	if (! VirtualProtectEx (Handle, (LPVOID)Address, Length, Oldprot, &Oldprot)) {
		false;
	}

	FlushInstructionCache (Handle, (LPCVOID)Address, Length);
	return Result && *Write == Length;
}


BOOL VmReadProcessMemory (
		_In_ const 	HANDLE 		Handle, 
		_In_ const 	UINT_PTR 	Address, 
		_Inout_ 	UINT8* 		ReadBytes, 
		_In_ const 	SIZE_T 		Length) 
{
	SIZE_T Read = 0;
	BOOL Result = ReadProcessMemory (Handle, (LPCVOID)Address, (LPVOID)ReadBytes, Length, &Read);

	return Result && Read == Length;
}


// TODO:
_native void cache_data(uintptr_t data, size_t size) {
	return;
}


_native void destroy_data(uintptr_t data, size_t size) {
	return;
}


typedef struct {
	UINT_PTR 	GuestAddr;
	UINT_PTR 	HostAddr;
	SIZE_T 		Length;
} PAGE_TABLE;


VM_DATA PAGE_TABLE PageTable [128] = { };
VM_DATA static SIZE_T PageCount = 0;


NATIVE_CALL BOOL MemoryRegister (
		_Out_ 		UINT_PTR* 	Guest, 
		_In_ const 	UINT_PTR 	Host, 
		_In_ const 	SIZE_T 		Size) 
{
	if (PageCount >= 128 || Host == 0 || Guest == 0) {
		return false;
	}
	if (*Guest == (UINT_PTR)0) {
		*Guest = (UINT_PTR)Host;
	}
	for (auto& Entry : PageTable) {
		if (Entry.GuestAddr == 0) {
			Entry = { *Guest, Host, Size };
			PageCount++;

			return true;
		}
	}
	return false;
}


NATIVE_CALL BOOL MemoryUnregister (
		_In_ const UINT_PTR Guest) 
{
	if (Guest == 0 || PageCount == 0) {
		return false;
	}
	for (size_t i = 0; i < PageCount; ++i) {
		if (PageTable [i].GuestAddr == Guest) {
			for (size_t j = i; j < PageCount - 1; ++j) {
				PageTable [j] = PageTable [j + 1];
			}

			PageTable [PageCount - 1] = { 0, 0, 0 };
			--PageCount;

			return true;
		}
	}
	return false;
}


NATIVE_CALL UINT8* MemoryCheck (
		_In_ const UINT_PTR guest) 
{
	if (Guest == 0) {
		return nullptr;
	}
	for (const auto& Entry : PageTable) {
		if (Guest >= Entry.GuestAddr && Guest < Entry.GuestAddr + Entry.Length) {
			uintptr_t Offset = Guest - Entry.GuestAddr;
			return (UINT8*) Entry.HostAddr + Offset; // risc-v usable address for calculating non-zero offsets (host[n + i])
		}
	}
	return nullptr;
}


template <typename T>
NATIVE_CALL VOID CheckMemory (
		_In_ 	const T		Type, 
		_Inout_ UINT_PTR* 	Address) 
{
	UINT_PTR Heap = MemoryCheck (Address); // check if this is v-heap memory. if found in the table, will return the real address.
	if (Heap) {  																	
		*Address = (UINT_PTR)Heap; 													
		return;
	} 																			
	if ((*Address) % sizeof (Type) != 0) {                                         	
		SetCsrTrap (Vmcs->hdw->Pc, LoadAddressMiss, 0, *Address, 1);       
	}                                                                      		
	if (! STACK_MEMORY_IN_BOUNDS (*Address) && ! PROCESS_MEMORY_IN_BOUNDS (*Address)) {		
		SetCsrTrap (Vmcs->Hdw->Pc, LoadAccessFault, 0, *Address, 1);      		
	} 																			
}


DWORD TranslateLinuxProt (
		_In_ const UINT32 Prot) 
{
	if (Prot == 0) {
		return PAGE_NOACCESS;
	}

	BOOL CanRead  = Prot & PROT_READ;
	BOOL CanWrite = Prot & PROT_WRITE;
	BOOL CanExec  = Prot & PROT_EXEC;

	if (CanExec) {
		if (CanWrite)
			return PAGE_EXECUTE_READWRITE;
		if (CanRead)
			return PAGE_EXECUTE_READ;
		return PAGE_EXECUTE;
	} else {
		if (CanWrite)
			return PAGE_READWRITE;
		if (CanRead)
			return PAGE_READONLY;
	}

	return PAGE_NOACCESS;
}
#endif // VMMU_H
