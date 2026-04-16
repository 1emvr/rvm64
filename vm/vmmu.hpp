#ifndef VMMU_H
#define VMMU_H
#include "../include/vmmain.hpp"

#define PROT_READ	0x1		
#define PROT_WRITE	0x2		
#define PROT_EXEC	0x4		
#define PROT_SEM	0x8	

	typedef struct {
		UINT_PTR 	GuestAddr;
		UINT_PTR 	HostAddr;
		SIZE_T 		Length;
	} PAGE_TABLE;

	VM_DATA EXEC_REGION PageTable [128] = { };
	VM_DATA static SIZE_T PageCount = 0;

	NATIVE_CALL BOOL MemoryRegister (_Out_ UINT_PTR* Guest, _In_ const UINT_PTR Host, _In_ const SIZE_T Length) {
		if (PageCount >= 128 || Host == 0 || Guest == 0) {
			return false;
		}
		if (*Guest == (UINT_PTR)0) {
			*Guest = (UINT_PTR)Host;
		}
		for (auto& Entry : PageTable) {
			if (Entry.GuestAddr == 0) {
				Entry = { *Guest, Host, Length };

				PageCount++;
				return true;
			}
		}
		return false;
	}

NATIVE_CALL BOOL MemoryUnregister (_In_ const UINT_PTR guest) {
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

NATIVE_CALL UINT8* MemoryCheck (_In_ const UINT_PTR guest) {
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

DWORD TranslateLinuxProt (_In_ const UINT32 Prot) {
	if (Prot == 0) return PAGE_NOACCESS;

	bool CanRead  = Prot & PROT_READ;
	bool CanWrite = Prot & PROT_WRITE;
	bool CanExec  = Prot & PROT_EXEC;

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
