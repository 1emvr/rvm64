#ifndef RVNI_H
#define RVNI_H
#include <windows.h>

#include "vmmain.hpp"
#include "vmrwx.hpp"
#include "vmmu.hpp"


VM_CALL VOID NativeCall (VOID);
NATIVE_CALL LPVOID ResolveRvniImport (_In_ const CHAR *SymName);


constexpr const char *C_OPEN 		= "_open";
constexpr const char *C_READ 		= "_read";
constexpr const char *C_WRITE 		= "_write";
constexpr const char *C_CLOSE 		= "_close";
constexpr const char *C_LSEEK 		= "_lseek";
constexpr const char *C_STAT64 		= "_stat64";
constexpr const char *C_MALLOC 		= "malloc";
constexpr const char *C_FREE 		= "free";
constexpr const char *C_MEMCPY 		= "memcpy";
constexpr const char *C_MEMSET 		= "memset";
constexpr const char *C_STRLEN 		= "strlen";
constexpr const char *C_STRCPY 		= "strcpy";
constexpr const char *C_MMAP 		= "mmap";
constexpr const char *C_MUNMAP 		= "munmap";
constexpr const char *C_MPROTECT 	= "mprotect";


VM_DATA UCRT_ALIAS AliasTable [] = {
	{ "open",  "_open"  }, 
	{ "read",  "_read"  }, 
	{ "write", "_write" }, 
	{ "close", "_close" }, 
	{ "exit",  "_exit"  }, 
	{ "mmap", 	"VirtualAlloc" }, 
	{ "munmap", "VirtualFree" }, 
	{ "mprotect", "VirtualProtect" }, 
};


typedef struct {
	const CHAR* Original;
	const CHAR* Alias;
} UCRT_ALIAS;


typedef struct _ucrt_function {
	const CHAR*	Name;
	LPVOID 		Address;

	enum {
		OPEN, READ, WRITE, CLOSE, LSEEK, STAT64, MALLOC, FREE,
		MEMCPY, MEMSET, STRLEN, STRCPY, MMAP, MUNMAP, MPROTECT,
		UNKNOWN
	} Typenum;

	union {
		INT 	(__cdecl* open)			(CHAR*, INT, INT);
		INT 	(__cdecl* read)			(INT, LPVOID, UINT);
		INT 	(__cdecl* write)		(INT, LPVOID, UINT);
		INT 	(__cdecl* close)		(INT);
		LONG 	(__cdecl* lseek)		(INT, LONG, INT);
		INT 	(__cdecl* stat64)		(const CHAR*, LPVOID);
		LPVOID 	(__cdecl* malloc)		(SIZE_T);
		VOID 	(__cdecl* free)			(LPVOID);
		LPVOID 	(__cdecl* memcpy)		(LPVOID, LPVOID, SIZE_T);
		LPVOID 	(__cdecl* memset)		(LPVOID, INT, SIZE_T);
		SIZE_T 	(__cdecl* strlen)		(CHAR *);
		CHAR * 	(__cdecl* strcpy)		(CHAR *, CHAR *);
		LPVOID 	(__stdcall* mmap)		(LPVOID, SIZE_T, DWORD, DWORD); 	// aliased to VirtualAlloc
		BOOL 	(__stdcall* munmap)		(LPVOID, SIZE_T, DWORD); 			// aliased to VirtualFree
		BOOL 	(__stdcall* mprotect)	(LPVOID, SIZE_T, DWORD, PDWORD); 	// aliased to VirtualProtect
	} Typecaster;
} UCRT_FUNCTION;


// NOTE: Gets populated during ResolveRvniImport at init.
DATA_SCN UCRT_FUNCTION FunctionTable [] = {
	{ .Address = 0, .Name = C_OPEN, 	.Typenum = UCRT_FUNCTION::OPEN		}, 
	{ .Address = 0, .Name = C_READ, 	.Typenum = UCRT_FUNCTION::READ		}, 
	{ .Address = 0, .Name = C_WRITE, 	.Typenum = UCRT_FUNCTION::WRITE 	}, 
	{ .Address = 0, .Name = C_CLOSE, 	.Typenum = UCRT_FUNCTION::CLOSE 	},
	{ .Address = 0, .Name = C_LSEEK, 	.Typenum = UCRT_FUNCTION::LSEEK 	}, 
	{ .Address = 0, .Name = C_STAT64, 	.Typenum = UCRT_FUNCTION::STAT64 	}, 
	{ .Address = 0, .Name = C_MALLOC, 	.Typenum = UCRT_FUNCTION::MALLOC 	}, 
	{ .Address = 0, .Name = C_FREE, 	.Typenum = UCRT_FUNCTION::FREE 		},
	{ .Address = 0, .Name = C_MEMCPY, 	.Typenum = UCRT_FUNCTION::MEMCPY 	}, 
	{ .Address = 0, .Name = C_MEMSET, 	.Typenum = UCRT_FUNCTION::MEMSET 	}, 
	{ .Address = 0, .Name = C_STRLEN, 	.Typenum = UCRT_FUNCTION::STRLEN 	}, 
	{ .Address = 0, .Name = C_STRCPY, 	.Typenum = UCRT_FUNCTION::STRCPY 	},
	{ .Address = 0, .Name = C_MMAP, 	.Typenum = UCRT_FUNCTION::MMAP 		}, 
	{ .Address = 0, .Name = C_MUNMAP, 	.Typenum = UCRT_FUNCTION::MUNMAP 	}, 
	{ .Address = 0, .Name = C_MPROTECT, .Typenum = UCRT_FUNCTION::MPROTECT 	},
};


NATIVE_CALL LPVOID ResolveRvniImport (
		_In_ const CHAR *SymName) 
{
	if (! Vmcs->Module.Kernel32 || ! Vmcs->Module.Ucrt) {
		SetCsrTrap (nullptr, ImageBadSymbol, 0, 0, true);
	}

	const CHAR *AliasName = SymName;

	for (auto& i : AliasTable) {
		if (strcmp (SymName, i.Original) == 0) {
			AliasName = (const CHAR*) i.Alias;
			break;
		}
	}

	LPVOID Native = (LPVOID) GetProcAddress (Vmcs->Module.Ucrt, AliasName); // resolve by the win32 equivalent. 

	if (! Native) {
		Native = (LPVOID) GetProcAddress (Vmcs->Module.Kernel32, AliasName);

		if (! Native) {
			SetCsrTrap (nullptr, ImageBadSymbol, 0, (UINT_PTR)AliasName, true);
		}
	}

	for (auto& f : FunctionTable) {
		if (MbsCmp (SymName, f.Name) == 0) {
			f.Address = Native;

			switch (f.Typenum) {
				case UCRT_FUNCTION::OPEN:   	f.Typecaster.open 		= (decltype(f.Typecaster.open))		Native; f.Address 	= Native; break;
				case UCRT_FUNCTION::READ:   	f.Typecaster.read 		= (decltype(f.Typecaster.read))		Native; f.Address 	= Native; break;
				case UCRT_FUNCTION::WRITE:  	f.Typecaster.write		= (decltype(f.Typecaster.write))	Native; f.Address 	= Native; break;
				case UCRT_FUNCTION::CLOSE:  	f.Typecaster.close 		= (decltype(f.Typecaster.close))	Native; f.Address 	= Native; break;
				case UCRT_FUNCTION::LSEEK:  	f.Typecaster.lseek 		= (decltype(f.Typecaster.lseek))	Native; f.Address 	= Native; break;
				case UCRT_FUNCTION::STAT64: 	f.Typecaster.stat64 	= (decltype(f.Typecaster.stat64))	Native; f.Address 	= Native; break;
				case UCRT_FUNCTION::MALLOC: 	f.Typecaster.malloc 	= (decltype(f.Typecaster.malloc))	Native; f.Address 	= Native; break;
				case UCRT_FUNCTION::FREE:   	f.Typecaster.free 		= (decltype(f.Typecaster.free))		Native; f.Address 	= Native; break;
				case UCRT_FUNCTION::MEMCPY: 	f.Typecaster.memcpy 	= (decltype(f.Typecaster.memcpy))	Native; f.Address 	= Native; break;
				case UCRT_FUNCTION::MEMSET: 	f.Typecaster.memset 	= (decltype(f.Typecaster.memset))	Native; f.Address 	= Native; break;
				case UCRT_FUNCTION::STRLEN: 	f.Typecaster.strlen 	= (decltype(f.Typecaster.strlen))	Native; f.Address 	= Native; break;
				case UCRT_FUNCTION::STRCPY: 	f.Typecaster.strcpy 	= (decltype(f.Typecaster.strcpy))	Native; f.Address 	= Native; break;
				case UCRT_FUNCTION::MMAP: 		f.Typecaster.mmap 		= (decltype(f.Typecaster.mmap))		Native; f.Address 	= Native; break;
				case UCRT_FUNCTION::MUNMAP:		f.Typecaster.munmap 	= (decltype(f.Typecaster.munmap))	Native; f.Address 	= Native; break;
				case UCRT_FUNCTION::MPROTECT:	f.Typecaster.mprotect 	= (decltype(f.Typecaster.mprotect))	Native; f.Address 	= Native; break;
				default:  SetCsrTrap (nullptr, ImageBadSymbol, 0, 0, true);
			}
			break;
		}
	}
	return Native;
}


VM_CALL VOID NativeCall () {
	UCRT_FUNCTION Api = { };

	for (auto &f : FunctionTable) {
		if (Vmcs->Hdw.Pc == (UINT_PTR)f.Address) {
			Api = &f;
			break;
		}
	}
	if (! Api.Address) {
		SetCsrTrap (Vmcs->Hdw.Pc, ImageBadSymbol, 0, Api.Typenum, true);
	}

	switch (Api.Typenum) {
		case UCRT_FUNCTION::OPEN: 
			{
				CHAR *Pathname = 0;
				INT Flags = 0, Mode = 0;

				RegRead (CHAR*, Pathname, A0);
				RegRead (INT, Flags, A1);
				RegRead (INT, Mode, A2);

				INT Result = Api.Typecaster.open (Pathname, Flags, Mode);
				RegWrite (INT, A0, Result);

				break;
			}
		case UCRT_FUNCTION::READ: 
			{
				INT Fd 		= 0;
				LPVOID Buf 	= 0;
				UINT Count 	= 0;

				RegRead (INT, Fd, A0);
				RegRead (LPVOID, Buf, A1);
				RegRead (UINT, Count, A2);

				INT Result = Api.Typecaster.read (Fd, Buf, Count);
				RegWrite (INT, A0, Result);

				break;
			}
		case UCRT_FUNCTION::WRITE: 
			{
				INT Fd 		= 0;
				LPVOID Buf 	= 0;
				UINT Count 	= 0;

				RegRead (INT, Fd, A0);
				RegRead (LPVOID, Buf, A1);
				RegRead (UINT, Count, A2);

				INT Result = Api.Typecaster.write (Fd, Buf, Count);
				RegWrite (INT, A0, Result);

				break;
			}
		case UCRT_FUNCTION::CLOSE: 
			{
				INT Fd = 0;
				RegRead (INT, Fd, A0);

				INT Result = Api.Typecaster.close (Fd);
				RegWrite (INT, A0, Result);

				break;
			}
		case UCRT_FUNCTION::LSEEK: 
			{
				INT Fd 		= 0;
				LONG Offset = 0;
				INT Whence 	= 0;

				RegRead (INT, Fd, A0);
				RegRead (LONG, Offset, A1);
				RegRead (INT, Whence, A2);

				LONG Result = Api.Typecaster.lseek (Fd, Offset, Whence);
				RegWrite (LONG, A0, Result);

				break;
			}
		case UCRT_FUNCTION::STAT64: 
			{
				const CHAR *Pathname 	= 0;
				LPVOID Statbuf 			= 0;

				RegRead (const CHAR*, Pathname, a0);
				RegRead (LPVOID, Statbuf, A1);

				INT Result = Api.Typecaster.stat64 (Pathname, Statbuf);
				RegWrite (INT, A0, Result);

				break;
			}
		case UCRT_FUNCTION::MALLOC: 
			{
				SIZE_T Size = 0;
				RegRead (SIZE_T, Size, A0);

				LPVOID Result = Api.Typecaster.malloc (SIZE);
				RegWrite (UINT_PTR, A0, Result);

				break;
			}
		case UCRT_FUNCTION::FREE: 
			{
				LPVOID Ptr = 0;
				RegRead (LPVOID, Ptr, A0);

				Api.Typecaster.free (Ptr);
				RegWrite (UINT_PTR, A0, 0);

				break;
			}
		case UCRT_FUNCTION::MEMCPY: 
			{
				LPVOID Dest = 0, *Src = 0;
				SIZE_T n = 0;

				RegRead (LPVOID, Dest, A0);
				RegRead (LPVOID, Src, A1);
				RegRead (SIZE_T, n, A2);

				LPVOID Result = Api.Typecaster.memcpy (Dest, Src, n);
				RegWrite (UINT_PTR, A0, Result);

				break;
			}
		case UCRT_FUNCTION::MEMSET: 
			{
				LPVOID Dest = 0;
				INT Value 	= 0;
				SIZE_T n  	= 0;

				RegRead (LPVOID, Dest, A0);
				RegRead (INT, Value, A1);
				RegRead (SIZE_T, n, A2);

				LPVOID Result = Api.Typecaster.memset (Dest, Value, n);
				RegWrite(UINT64, A0, Result);

				break;
			}
		case ucrt_function::STRLEN: 
			{
				CHAR *s = 0;
				RegRead (CHAR*, s, A0);

				SIZE_T Result = Api.Typecaster.strlen (s);
				RegWrite (SIZE_T, A0, Result);

				break;
			}
		case UCRT_FUNCTION::STRCPY: 
			{
				CHAR *Dest = 0, *Src = 0;

				RegRead (CHAR*, Dest, A0);
				RegRead (CHAR*, Src, A1);

				CHAR *Result = Api.Typecaster.strcpy (Dest, Src);
				RegWrite (UINT_PTR, A0, Result);

				break;
			}
		case UCRT_FUNCTION::MMAP: 
			{
				LPVOID Addr = 0;
				SIZE_T Len 	= 0;
				DWORD prot 	= 0, Flags = 0;

				RegRead (LPVOID, Addr, A0);
				RegRead (SIZE_T, Len, A1);
				RegRead (DWORD, Prot, A2);
				RegRead (DWORD, Flags, A3);

				LPVOID HostMem = Api.Typecaster.mmap (
						nullptr, len, MEM_COMMIT | MEM_RESERVE, LINUX_TO_WIN_PROT (prot));

				if (! MemoryUnregister ((UINT_PTR*)&Addr, HostMem, Len)) {
					SetCsrTrap (Vmcs->Hdw.Pc, OutOfMemory, 0, (UINT_PTR)Addr, true);
				}

				RegWrite(UINT_PTR, A0, Addr);
				break;
			}
		case UCRT_FUNCTION::MUNMAP: 
			{
				LPVOID Addr = 0;
				SIZE_T Len 	= 0;

				RegRead (LPVOID, Addr, A0);
				RegRead (SIZE_T, Len, A1);

				auto GuestMem 	= (UINT_PTR)Addr;
				LPVOID HostMem 	= MemoryCheck (GuestMem);
				BOOL Unregister = MemoryUnregister (GuestMem);

				INT Result = Api.Typecaster.munmap (HostMem, Len, MEM_RELEASE);
				RegWrite (INT, A0, ((Result && Unregister) ? 0 : -1));

				break;
			}
		case UCRT_FUNCTION::MPROTECT: 
			{
				LPVOID Addr = 0;
				SIZE_T Len 	= 0;
				DWORD Prot 	= 0, Old = 0;

				RegRead (LPVOID, Addr, A0);
				RegRead (SIZE_T, Len, A1);
				RegRead (DWORD, Prot, A2);

				auto Func = Api.Typecaster.mprotect (Addr, Len, Prot, &Old);
				RegWrite (INT, A0, Func ? 0 : -1);

				break;
			}
		default: 
			{
				SetCsrTrap (Vmcs->Hdw.Pc, IllegalInstruction, 0, Api.Typenum, true);
			}
	}
}
#endif // RVNI_H
