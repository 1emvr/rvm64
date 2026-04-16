#ifndef RVNI_H
#define RVNI_H
#include <windows.h>

#include "../include/vmmain.hpp"
#include "../include/vmcommon.hpp"

#include "vmrwx.hpp"
#include "vmmu.hpp"

constexpr const char *C_OPEN = "_open";
constexpr const char *C_READ = "_read";
constexpr const char *C_WRITE = "_write";
constexpr const char *C_CLOSE = "_close";
constexpr const char *C_LSEEK = "_lseek";
constexpr const char *C_STAT64 = "_stat64";
constexpr const char *C_MALLOC = "malloc";
constexpr const char *C_FREE = "free";
constexpr const char *C_MEMCPY = "memcpy";
constexpr const char *C_MEMSET = "memset";
constexpr const char *C_STRLEN = "strlen";
constexpr const char *C_STRCPY = "strcpy";
constexpr const char *C_MMAP = "mmap";
constexpr const char *C_MUNMAP = "munmap";
constexpr const char *C_MPROTECT = "mprotect";

	struct ucrt_function {
		LPVOID Address;
		const CHAR *name;

		enum {
			OPEN, READ, WRITE, CLOSE, LSEEK, STAT64, MALLOC, FREE,
			MEMCPY, MEMSET, STRLEN, STRCPY, MMAP, MUNMAP, MPROTECT,
			UNKNOWN
		} typenum;

		union {
			INT 	(__cdecl* open)(PCHAR, INT, INT);
			INT 	(__cdecl* read)(INT, LPVOID, UINT);
			INT 	(__cdecl* write)(INT, LPVOID, UINT);
			INT 	(__cdecl* close)(INT);
			LONG 	(__cdecl* lseek)(INT, LONG, INT);
			INT 	(__cdecl* stat64)(const CHAR *, LPVOID);
			LPVOID 	(__cdecl* malloc)(SIZE_T);
			VOID 	(__cdecl* free)(LPVOID);
			LPVOID 	(__cdecl* memcpy)(LPVOID, LPVOID, SIZE_T);
			LPVOID 	(__cdecl* memset)(LPVOID, INT, SIZE_T);
			SIZE_T 	(__cdecl* strlen)(CHAR *);
			CHAR * 	(__cdecl* strcpy)(CHAR *, CHAR *);
			LPVOID 	(__stdcall* mmap)(LPVOID, SIZE_T, DWORD, DWORD); // aliased to VirtualAlloc
			BOOL 	(__stdcall* munmap)(LPVOID, SIZE_T, DWORD); // aliased to VirtualFree
			BOOL 	(__stdcall* mprotect)(LPVOID, SIZE_T, DWORD, PDWORD); // aliased to VirtualProtect
		} Typecaster;
	};

	VM_DATA UCRT_FUNCTION FunctionTable[] = {
		{ .Address = 0, .name = C_OPEN, 	.typenum = UCRT_FUNCTION::OPEN		}, 
		{ .Address = 0, .name = C_READ, 	.typenum = UCRT_FUNCTION::READ		}, 
		{ .Address = 0, .name = C_WRITE, 	.typenum = UCRT_FUNCTION::WRITE 	}, 
		{ .Address = 0, .name = C_CLOSE, 	.typenum = UCRT_FUNCTION::CLOSE 	},
		{ .Address = 0, .name = C_LSEEK, 	.typenum = UCRT_FUNCTION::LSEEK 	}, 
		{ .Address = 0, .name = C_STAT64, 	.typenum = UCRT_FUNCTION::STAT64 	}, 
		{ .Address = 0, .name = C_MALLOC, 	.typenum = UCRT_FUNCTION::MALLOC 	}, 
		{ .Address = 0, .name = C_FREE, 	.typenum = UCRT_FUNCTION::FREE 		},
		{ .Address = 0, .name = C_MEMCPY, 	.typenum = UCRT_FUNCTION::MEMCPY 	}, 
		{ .Address = 0, .name = C_MEMSET, 	.typenum = UCRT_FUNCTION::MEMSET 	}, 
		{ .Address = 0, .name = C_STRLEN, 	.typenum = UCRT_FUNCTION::STRLEN 	}, 
		{ .Address = 0, .name = C_STRCPY, 	.typenum = UCRT_FUNCTION::STRCPY 	},
		{ .Address = 0, .name = C_MMAP, 	.typenum = UCRT_FUNCTION::MMAP 		}, 
		{ .Address = 0, .name = C_MUNMAP, 	.typenum = UCRT_FUNCTION::MUNMAP 	}, 
		{ .Address = 0, .name = C_MPROTECT, .typenum = UCRT_FUNCTION::MPROTECT 	},
	};

	struct UCRT_ALIAS {
		const CHAR *Original;
		const CHAR *Alias;
	};
	VM_DATA UCRT_ALIAS AliasTable [] = {
		{ "open",  "_open"  }, { "read",  "_read"  }, { "write", "_write" }, { "close", "_close" }, { "exit",  "_exit"  }, 
		{ "mmap", "VirtualAlloc" }, { "munmap", "VirtualFree" }, { "mprotect", "VirtualProtect" }, 
	};

	Native_CALL LPVOID ResolveRvniImport (const CHAR *SymName) {
		static HMODULE Ucrt = LoadLibraryA ("ucrtbase.dll");
		static HMODULE Kern32 = LoadLibraryA ("kernel32.dll");

		if (! Ucrt || ! Kern32) {
			CSR_SET_TRAP (nullptr, ImageBadSymbol, 0, 0, 1);
		}

		const CHAR *AliasName = SymName;

		for (auto& i : AliasTable) {
			if (strcmp (SymName, i.original) == 0) {
				AliasName = (const CHAR*) i.Alias;
				break;
			}
		}

		LPVOID Native = (LPVOID) GetProcAddress (Ucrt, AliasName);

		if (! Native) {
			Native = (LPVOID) GetProcAddress (Kern32, AliasName);

			if (! Native) {
				CSR_SET_TRAP (nullptr, ImageBadSymbol, 0, (UINT_PTR)AliasName, 1);
			}
		}

		for (auto& f : FunctionTable) {
			if (strcmp (SymName, f.Name) == 0) {
				f.Address = Native;
				 
				switch (f.Typenum) {
					case UCRT_FUNCTION::OPEN:   	f.Typecaster.open 		= (decltype(f.Typecaster.open))Native; break;
					case UCRT_FUNCTION::READ:   	f.Typecaster.read 		= (decltype(f.Typecaster.read))Native; break;
					case UCRT_FUNCTION::WRITE:  	f.Typecaster.write		= (decltype(f.Typecaster.write))Native; break;
					case UCRT_FUNCTION::CLOSE:  	f.Typecaster.close 		= (decltype(f.Typecaster.close))Native; break;
					case UCRT_FUNCTION::LSEEK:  	f.Typecaster.lseek 		= (decltype(f.Typecaster.lseek))Native; break;
					case UCRT_FUNCTION::STAT64: 	f.Typecaster.stat64 	= (decltype(f.Typecaster.stat64))Native; break;
					case UCRT_FUNCTION::MALLOC: 	f.Typecaster.malloc 	= (decltype(f.Typecaster.malloc))Native; break;
					case UCRT_FUNCTION::FREE:   	f.Typecaster.free 		= (decltype(f.Typecaster.free))Native; break;
					case UCRT_FUNCTION::MEMCPY: 	f.Typecaster.memcpy 	= (decltype(f.Typecaster.memcpy))Native; break;
					case UCRT_FUNCTION::MEMSET: 	f.Typecaster.memset 	= (decltype(f.Typecaster.memset))Native; break;
					case UCRT_FUNCTION::STRLEN: 	f.Typecaster.strlen 	= (decltype(f.Typecaster.strlen))Native; break;
					case UCRT_FUNCTION::STRCPY: 	f.Typecaster.strcpy 	= (decltype(f.Typecaster.strcpy))Native; break;
					case UCRT_FUNCTION::MMAP: 		f.Typecaster.mmap 		= (decltype(f.Typecaster.mmap))Native; break;
					case UCRT_FUNCTION::MUNMAP:		f.Typecaster.munmap 	= (decltype(f.Typecaster.munmap))Native; break;
					case UCRT_FUNCTION::MPROTECT:	f.Typecaster.mprotect 	= (decltype(f.Typecaster.mprotect))Native; break;
					default:  CSR_SET_TRAP(nullptr, image_bad_symbol, 0, 0, 1);
				}
				break;
			}
		}
		return Native;
	}

VMCALL VOID NativeCall () {
	UCRT_FUNCTION *Api = nullptr;

	for (auto &f : FunctionTable) {
		if (Vmcs->Gpr->Pc == (UINT_PTR)f.Address) {
			Api = &f;
			break;
		}
	}
	if (! Api) {
		CSR_SET_TRAP (Vmcs->Gpr->Pc, ImageBadSymbol, 0, Vmcs->Gpr->Pc, 1);
	}

	switch (Api->Typenum) {
		case UCRT_FUNCTION::OPEN: 
			{
				CHAR *Pathname = 0;
				INT Flags = 0, mode = 0;

				RegRead (CHAR*, Pathname, Regenum::a0);
				RegRead (INT, Flags, Regenum::a1);
				RegRead (INT, Mode, Regenum::a2);

				INT Result = Api->Typecaster.open (Pathname, Flags, Mode);
				RegWrite (int, Regenum::a0, Result);

				break;
			}
		case UCRT_FUNCTION::READ: 
			{
				INT Fd 		= 0;
				LPVOID Buf 	= 0;
				UINT count 	= 0;

				RegRead (INT, Fd, Regenum::a0);
				RegRead (LPVOID, Buf, Regenum::a1);
				RegRead (UINT, Count, Regenum::a2);

				INT Result = Api->Typecaster.read (Fd, Buf, Count);
				RegWrite (INT, Regenum::a0, Result);

				break;
			}
		case UCRT_FUNCTION::WRITE: 
			{
				INT Fd 		= 0;
				LPVOID Buf 	= 0;
				UINT Count 	= 0;

				RegRead (INT, Fd, Regenum::a0);
				RegRead (LPVOID, Buf, Regenum::a1);
				RegRead (UINT, Count, Regenum::a2);

				INT Result = Api->Typecaster.write (Fd, Buf, Count);
				RegWrite (INT, Regenum::a0, Result);

				break;
			}
		case UCRT_FUNCTION::CLOSE: 
			{
				INT Fd = 0;
				RegRead (INT, Fd, Regenum::a0);

				INT Result = Api->Typecaster.close (Fd);
				RegWrite (INT, Regenum::a0, Result);

				break;
			}
		case UCRT_FUNCTION::LSEEK: 
			{
				INT Fd 		= 0;
				LONG Offset = 0;
				INT Whence 	= 0;

				RegRead (INT, Fd, Regenum::a0);
				RegRead (LONG, Offset, Regenum::a1);
				RegRead (INT, Whence, Regenum::a2);

				LONG Result = Api->Typecaster.lseek (Fd, Offset, Whence);
				RegWrite (LONG, Regenum::a0, Result);

				break;
			}
		case UCRT_FUNCTION::STAT64: 
			{
				const CHAR *Pathname 	= 0;
				LPVOID Statbuf 			= 0;

				RegRead (const CHAR*, Pathname, Regenum::a0);
				RegRead (LPVOID, Statbuf, Regenum::a1);

				INT Result = Api->Typecaster.stat64 (Pathname, Statbuf);
				RegWrite (INT, Regenum::a0, Result);

				break;
			}
		case UCRT_FUNCTION::MALLOC: 
			{
				SIZE_T Size = 0;
				RegRead (SIZE_T, Size, Regenum::a0);

				LPVOID Result = Api->Typecaster.malloc (SIZE);
				RegWrite (UINT_PTR, Regenum::a0, Result);

				break;
			}
		case UCRT_FUNCTION::FREE: 
			{
				LPVOID Ptr = 0;
				RegRead (LPVOID, Ptr, Regenum::a0);

				Api->Typecaster.free (Ptr);
				RegWrite (UINT_PTR, Regenum::a0, 0);

				break;
			}
		case UCRT_FUNCTION::MEMCPY: 
			{
				LPVOID Dest = 0, *Src = 0;
				SIZE_T n = 0;

				RegRead (LPVOID, Dest, Regenum::a0);
				RegRead (LPVOID, Src, Regenum::a1);
				RegRead (SIZE_T, n, Regenum::a2);

				LPVOID Result = Api->Typecaster.memcpy (Dest, Src, n);
				RegWrite (UINT_PTR, Regenum::a0, Result);

				break;
			}
		case UCRT_FUNCTION::MEMSET: 
			{
				LPVOID Dest = 0;
				INT Value 	= 0;
				SIZE_T n  	= 0;

				RegRead (LPVOID, Dest, Regenum::a0);
				RegRead (INT, Value, Regenum::a1);
				RegRead (SIZE_T, n, Regenum::a2);

				LPVOID Result = Api->Typecaster.memset (Dest, Value, n);
				RegWrite(UINT64, Regenum::a0, Result);

				break;
			}
		case ucrt_function::STRLEN: 
			{
				CHAR *s = 0;
				RegRead (CHAR*, s, Regenum::a0);

				SIZE_T Result = Api->Typecaster.strlen (s);
				RegWrite (SIZE_T, Regenum::a0, Result);

				break;
			}
		case UCRT_FUNCTION::STRCPY: 
			{
				CHAR *Dest = 0, *Src = 0;

				RegRead (CHAR*, Dest, Regenum::a0);
				RegRead (CHAR*, Src, Regenum::a1);

				CHAR *Result = Api->Typecaster.strcpy (Dest, Src);
				RegWrite (UINT_PTR, Regenum::a0, Result);

				break;
			}
		case UCRT_FUNCTION::MMAP: 
			{
				LPVOID Addr = 0;
				SIZE_T Len 	= 0;
				DWORD prot 	= 0, Flags = 0;

				RegRead (LPVOID, Addr, Regenum::a0);
				RegRead (SIZE_T, Len, Regenum::a1);
				RegRead (DWORD, Prot, Regenum::a2);
				RegRead (DWORD, Flags, Regenum::a3);

				LPVOID HostMem = Api->Typecaster.mmap (
						nullptr, len, MEM_COMMIT | MEM_RESERVE, LINUX_TO_WIN_PROT (prot));

				if (! MemoryUnregister ((UINT_PTR*)&Addr, HostMem, Len)) {
					CSR_SET_TRAP (Vmcs->Gpr->Pc, OutOfMemory, 0, (UINT_PTR)Addr, 1);
				}

				RegWrite(UINT_PTR, Regenum::a0, Addr);
				break;
			}
		case UCRT_FUNCTION::MUNMAP: 
			{
				LPVOID Addr = 0;
				SIZE_T Len 	= 0;

				RegRead (LPVOID, Addr, Regenum::a0);
				RegRead (SIZE_T, Len, Regenum::a1);

				auto GuestMem 	= (UINT_PTR)Addr;
				LPVOID HostMem 	= MemoryCheck (GuestMem);
				BOOL Unregister = MemoryUnregister (GuestMem);

				INT Result = Api->Typecaster.munmap (HostMem, Len, MEM_RELEASE);
				RegWrite (INT, Regenum::a0, ((Result && Unregister) ? 0 : -1));

				break;
			}
		case UCRT_FUNCTION::MPROTECT: 
			{
				LPVOID Addr = 0;
				SIZE_T Len 	= 0;
				DWORD Prot 	= 0, Old = 0;

				RegRead (LPVOID, Addr, Regenum::a0);
				RegRead (SIZE_T, Len, Regenum::a1);
				RegRead (DWORD, Prot, Regenum::a2);

				auto Func = Api->Typecaster.mprotect (Addr, Len, Prot, &Old);
				RegWrite (INT, Regenum::a0, Func ? 0 : -1);

				break;
			}
		default: 
			{
				CSR_SET_TRAP (Vmcs->Gpr->Pc, IllegalInstruction, 0, Api->Typenum, 1);
			}
	}
}
#endif // RVNI_H
