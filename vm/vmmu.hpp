#ifndef VMMU_H
#define VMMU_H
#include "../include/vmmain.hpp"

#define PROT_READ	0x1		
#define PROT_WRITE	0x2		
#define PROT_EXEC	0x4		
#define PROT_SEM	0x8	


/*
 * NOTE: Anything other than a branch, execute, native call, or shutdown will be treated as a violation.
 *
 * NOTE: Changing to arena allocation. Starting rvm64 will allocate 1 space for all programs.
 * When a program starts running the MMU will reserve memory, register & manage that memory. 
 * The arena will continue to live until shutdown. Programs will be zeroed and released to the MMU instead of deallocating system memory.
 */

LONG CALLBACK InterruptHandler (
		_In_ const PEXCEPTION_POINTERS 	exception_info, 
		_In_ const UINT8 				machine_index) 
{
	DWORD code 				= exception_info->ExceptionRecord->ExceptionCode;
	CONTEXT *win_context 	= exception_info->ContextRecord;

	g_vmcs->t_hardware [machine_index].csr.cause 	= code;
	g_vmcs->t_hardware [machine_index].csr.epc 		= win_context->Rip;

	if (code == STATUS_SINGLE_STEP) {
		return EXCEPTION_CONTINUE_SEARCH;
	}
	if (Code != RVM_TRAP_EXCEPTION) { 
		longjmp (Vmcs->Context->Interrupt, true);
	}

	switch (Vmcs->Csr.Cause) {
		case EnvExecute: 
			{
				VOID (WINAPI* Memory) (VOID) = (VOID (WINAPI*) (VOID)) Vmcs->Hdw.Pc;
				Memory ();
				break;
			}
		case EnvNative: 
			{
				NativeCall ();
				break;
			}
		case EnvShutdown: 	
			longjmp (Vmcs->Context->Shutdown, true);

		default:  			
			longjmp (Vmcs->Context->Interrupt, true); 
	}
	return EXCEPTION_CONTINUE_EXECUTION;
}


ARENA* NATIVE_CALL arena_alloc (_In_ const UINT64 size) {
	ARENA *a = (ARENA*)VirtualAlloc (nullptr, sizeof (ARENA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!a) return nullptr; 

	a->data = (UINT8*)VirtualAlloc (nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!a->data) {
		VirtualFree ((LPVOID)a, 0, MEM_RELEASE);
		return nullptr; 
	}

	a->capacity = size;
	a->used 	= 0;
	a->entries 	= nullptr;
	a->count 	= 0;
	return a;
}


ARENA* NATIVE_CALL arena_realloc (
		_In_ const ARENA *a, 
		_In_ const UINT64 size) 
{
	if (!a || a->capacity > size) {
		return nullptr;
	}

	ARENA *new_a = (ARENA*)VirtualAlloc (nullptr, sizeof (ARENA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!new_a) return nullptr; 

	new_a->data = (UINT8*)VirtualAlloc (nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!new_a->data) {
		VirtualFree ((LPVOID)new_a, 0, MEM_RELEASE);
		return nullptr; 
	}
	if (a->data) {
		MoveMemory ((LPVOID)new_a->data, (const LPVOID)a->data, a->used);
		VirtualFree ((LPVOID)a->data, 0, MEM_RELEASE);
	}

	a_new->capacity = size;
	a_new->used 	= a->used;
	a_new->entries 	= a->entries;
	a_new->count 	= a->count;

	VirtualFree ((LPVOID)a, 0, MEM_RELEASE);
	return a_new;
}


VOID NATIVE_CALL arena_release (_In_ const ARENA *a) {
	if (!a) return;
	if (a->data) {
		VirtualFree ((LPVOID)a->data, 0, MEM_RELEASE);
	}

	a->capacity = 0;
	a->used 	= 0;
	a->entries 	= 0;
	a->count 	= 0;

	VirtualFree ((LPVOID)a, 0, MEM_RELEASE);
}


VOID NATIVE_CALL rvm64_memory_init () {
	g_vmcs->code_arena = (UINT64) arena_alloc (DEFAULT_ARENA_SIZE); 
	g_vmcs->heap_arena = (UINT64) arena_alloc (DEFAULT_ARENA_SIZE); 

	if (!g_vmcs->code_arena || !g_vmcs->heap_arena) {
		csr_trap (nullptr, GetLastError (), 0, 0, 1);
		return;
	}

	g_vmcs->modules.kernel32 = GetModuleHandle ("kernel32.dll"); // TODO: switch to dyna-modules
	g_vmcs->modules.ucrtbase = GetModuleHandle ("ucrtbase.dll");
}


BOOL write_vm_memory (
		_In_ const 	HANDLE 		handle, 
		_In_ const 	UINT_PTR 	address, 
		_In_ const 	UINT8*		buffer, 
		_In_ const 	SIZE_T 		length, 
		_Out_ 		SIZE_T*		write) 
{
	DWORD oldprot = 0;
	if (! VirtualProtectEx (handle, (LPVOID)address, length, PAGE_EXECUTE_READWRITE, &oldprot)) { 
		return false;
	}

	BOOL result = WriteProcessMemory (handle, (LPVOID)address, buffer, length, write); // absolutely no protections lol
	if (! VirtualProtectEx (handle, (LPVOID)address, length, oldprot, &oldprot)) {
		false;
	}

	FlushInstructionCache (handle, (LPCVOID)address, length);
	return result && *write == length;
}


BOOL read_vm_memory (
		_In_ const 	HANDLE 		handle, 
		_In_ const 	UINT_PTR 	address, 
		_Inout_ 	UINT8* 		read_buffer, 
		_In_ const 	SIZE_T 		length) 
{
	SIZE_T read = 0;
	BOOL result = ReadProcessMemory (handle, (LPCVOID)address, (LPVOID)read_buffer, length, &read);

	return result && read == length;
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


NATIVE_CALL UINT8* SearchPageTable (
		_In_ const UINT_PTR Guest) 
{
	if (Guest == 0) {
		return nullptr;
	}
	for (const auto& Entry : PageTable) {
		if (Guest >= Entry.GuestAddr && 
			Guest < Entry.GuestAddr + Entry.Length) 
		{
			UINT_PTR Offset = Guest - Entry.GuestAddr;
			return (UINT8*) Entry.HostAddr + Offset; // risc-v usable address for calculating non-zero offsets (host[n + i])
		}
	}
	return nullptr;
}


#define RegRead (T, dst, reg_idx) 	dst = (T)Vmcs->Hdw->Regs [(reg_idx)]
#define ScrRead (T, dst, scr_idx) 	dst = (T)Vmcs->Hdw->Scratch [(scr_idx)]
#define MemRead (T, retval, addr)  	MemorySecurityCheck (T, addr); retval = *(T *)(addr);

#define RegWrite (T, reg_idx, src) 	if (reg_idx != 0) Vmcs->Hdw->Regs [(reg_idx)] = (T)(src);
#define ScrWrite (T, scr_idx, src) 	if (scr_idx <= imm) Vmcs->Hdw->Scratch [(scr_idx)] = (T)(src);
#define MemWrite (T, addr, value)  	MemorySecurityCheck (T, addr); *(T *)(addr) = value;


template <typename T>
VOID MemorySecurityCheck (
		_In_ const T 	AccessType, 
		_In_ UINT_PTR* 	Address) 
{
	UINT_PTR Host = SearchPageTable (Address); 
	if (Host) {  																	
		Address = Host; 													
	} 																			
	if ((Address) % sizeof (AccessType) != 0) {                                         		
		SetCsrTrap (Vmcs->Hdw->Pc, StoreAmoAddressMiss, 0, Address, true);  
	}                                                                      		
	if (! STACK_MEMORY_IN_BOUNDS (Address) && 
		! PROCESS_MEMORY_IN_BOUNDS (Address)) 
	{		
		SetCsrTrap (Vmcs->Hdw->Pc, StoreAmoAccessFault, 0, Address, true);		
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
