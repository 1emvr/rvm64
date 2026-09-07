#ifndef RVNI_H
#define RVNI_H
#include <windows.h>

#include "vmmain.hpp"
#include "vmrwx.hpp"
#include "vmmu.hpp"


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


typedef struct _ucrt_function {
	const CHAR*	call_name;

	enum {
		OPEN, READ, WRITE, CLOSE, LSEEK, STAT64, MALLOC, FREE,
		MEMCPY, MEMSET, STRLEN, STRCPY, MMAP, MUNMAP, MPROTECT,
		UNKNOWN
	} typenum;

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
	} typecaster;
} UCRT_FUNCTION;


UCRT_FUNCTION DATA_SCN FunctionTable [] = {
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


typedef struct {
	const CHAR* org_name;
	const CHAR* alias;
} UCRT_ALIAS;


UCRT_ALIAS VM_DATA alias_table [] = {
	{ "open",  "_open"  }, { "read",  "_read"  }, { "write", "_write" }, 
	{ "close", "_close" }, { "exit",  "_exit"  }, { "mmap", 	"VirtualAlloc" }, 
	{ "munmap", "VirtualFree" }, { "mprotect", "VirtualProtect" }, 
};


namespace rvni
{
	LPVOID VM_CALL rvni_import (
			_In_ const CHAR *sym_name) 
	{
		if (! g_vmcs->modules.kernel32 || ! g_vmcs->modules.ucrt) {
			SetCsrTrap (nullptr, ImageBadSymbol, 0, 0, true);
		}

		const CHAR *alias = sym_name;

		for (auto& i : alias_table) {
			if (strcmp (sym_name, i.org_name) == 0) {
				aliasName = (const CHAR*) i.alias;
				break;
			}
		}

		LPVOID real_addr = (LPVOID) GetProcAddress (Vmcs->Module.Ucrt, aliasName); // resolve by the win32 equivalent. 

		if (! real_addr) {
			real_addr = (LPVOID) GetProcAddress (Vmcs->Module.Kernel32, aliasName);

			if (! real_addr) {
				SetCsrTrap (nullptr, ImageBadSymbol, 0, (UINT_PTR)aliasName, true);
			}
		}

		for (auto& f : FunctionTable) {
			if (MbsCmp (sym_name, f.Name) == 0) {
				f.Address = real_addr;

				switch (f.Typenum) {
					case UCRT_FUNCTION::OPEN:   	f.typecaster.open 		= (decltype(f.typecaster.open))		real_addr;
					case UCRT_FUNCTION::READ:   	f.typecaster.read 		= (decltype(f.typecaster.read))		real_addr; 
					case UCRT_FUNCTION::WRITE:  	f.typecaster.write		= (decltype(f.typecaster.write))	real_addr; 
					case UCRT_FUNCTION::CLOSE:  	f.typecaster.close 		= (decltype(f.typecaster.close))	real_addr; 
					case UCRT_FUNCTION::LSEEK:  	f.typecaster.lseek 		= (decltype(f.typecaster.lseek))	real_addr; 
					case UCRT_FUNCTION::STAT64: 	f.typecaster.stat64 	= (decltype(f.typecaster.stat64))	real_addr; 
					case UCRT_FUNCTION::MALLOC: 	f.typecaster.malloc 	= (decltype(f.typecaster.malloc))	real_addr; 
					case UCRT_FUNCTION::FREE:   	f.typecaster.free 		= (decltype(f.typecaster.free))		real_addr; 
					case UCRT_FUNCTION::MEMCPY: 	f.typecaster.memcpy 	= (decltype(f.typecaster.memcpy))	real_addr; 
					case UCRT_FUNCTION::MEMSET: 	f.typecaster.memset 	= (decltype(f.typecaster.memset))	real_addr; 
					case UCRT_FUNCTION::STRLEN: 	f.typecaster.strlen 	= (decltype(f.typecaster.strlen))	real_addr; 
					case UCRT_FUNCTION::STRCPY: 	f.typecaster.strcpy 	= (decltype(f.typecaster.strcpy))	real_addr; 
					case UCRT_FUNCTION::MMAP: 		f.typecaster.mmap 		= (decltype(f.typecaster.mmap))		real_addr; 
					case UCRT_FUNCTION::MUNMAP:		f.typecaster.munmap 	= (decltype(f.typecaster.munmap))	real_addr; 
					case UCRT_FUNCTION::MPROTECT:	f.typecaster.mprotect 	= (decltype(f.typecaster.mprotect))	real_addr; 
					default:  SetCsrTrap (nullptr, ImageBadSymbol, 0, 0, true);
				}
				break;
			}
		}
		return real_addr;
	}


	VOID VM_CALL rvni_exit () {
		UCRT_FUNCTION *Api = nullptr;

		for (auto &f : FunctionTable) {
			if (Vmcs->Hdw.Pc == (UINT_PTR)f.Address) {
				Api = &f;
				break;
			}
		}
		if (! Api || ! Api->Address) {
			SetCsrTrap (Vmcs->Hdw.Pc, ImageBadSymbol, 0, Api->Typenum, true);
		}

		switch (Api->Typenum) {
			case UCRT_FUNCTION::OPEN: 
				{
					CHAR *Pathname = 0;
					INT Flags = 0, Mode = 0;

					reg_read (CHAR*, Pathname, A0);
					reg_read (INT, Flags, A1);
					reg_read (INT, Mode, A2);

					INT Result = Api->typecaster.open (Pathname, Flags, Mode);

					reg_write (INT, A0, Result);
					break;
				}
			case UCRT_FUNCTION::READ: 
				{
					INT Fd 		= 0;
					LPVOID Buf 	= 0;
					UINT Count 	= 0;

					reg_read (INT, Fd, A0);
					reg_read (LPVOID, Buf, A1);
					reg_read (UINT, Count, A2);

					INT Result = Api->typecaster.read (Fd, Buf, Count);

					reg_write (INT, A0, Result);
					break;
				}
			case UCRT_FUNCTION::WRITE: 
				{
					INT Fd 		= 0;
					LPVOID Buf 	= 0;
					UINT Count 	= 0;

					reg_read (INT, Fd, A0);
					reg_read (LPVOID, Buf, A1);
					reg_read (UINT, Count, A2);

					INT Result = Api->typecaster.write (Fd, Buf, Count);

					reg_write (INT, A0, Result);
					break;
				}
			case UCRT_FUNCTION::CLOSE: 
				{
					INT Fd = 0;
					reg_read (INT, Fd, A0);

					INT Result = Api->typecaster.close (Fd);

					reg_write (INT, A0, Result);
					break;
				}
			case UCRT_FUNCTION::LSEEK: 
				{
					INT Fd 		= 0;
					LONG Offset = 0;
					INT Whence 	= 0;

					reg_read (INT, Fd, A0);
					reg_read (LONG, Offset, A1);
					reg_read (INT, Whence, A2);

					LONG Result = Api->typecaster.lseek (Fd, Offset, Whence);

					reg_write (LONG, A0, Result);
					break;
				}
			case UCRT_FUNCTION::STAT64: 
				{
					const CHAR *Pathname 	= 0;
					LPVOID Statbuf 			= 0;

					reg_read (const CHAR*, Pathname, a0);
					reg_read (LPVOID, Statbuf, A1);

					INT Result = Api->typecaster.stat64 (Pathname, Statbuf);

					reg_write (INT, A0, Result);
					break;
				}
			case UCRT_FUNCTION::MALLOC: 
				{
					SIZE_T Size = 0;
					reg_read (SIZE_T, Size, A0);

					LPVOID Result = Api->typecaster.malloc (SIZE);

					reg_write (UINT_PTR, A0, Result);
					break;
				}
			case UCRT_FUNCTION::FREE: 
				{
					LPVOID Ptr = 0;
					reg_read (LPVOID, Ptr, A0);

					Api->typecaster.free (Ptr);

					reg_write (UINT_PTR, A0, 0);
					break;
				}
			case UCRT_FUNCTION::MEMCPY: 
				{
					LPVOID Dest = 0, *Src = 0;
					SIZE_T n = 0;

					reg_read (LPVOID, Dest, A0);
					reg_read (LPVOID, Src, A1);
					reg_read (SIZE_T, n, A2);

					LPVOID Result = Api->typecaster.memcpy (Dest, Src, n);

					reg_write (UINT_PTR, A0, Result);
					break;
				}
			case UCRT_FUNCTION::MEMSET: 
				{
					LPVOID Dest = 0;
					INT Value 	= 0;
					SIZE_T n  	= 0;

					reg_read (LPVOID, Dest, A0);
					reg_read (INT, Value, A1);
					reg_read (SIZE_T, n, A2);

					LPVOID Result = Api->typecaster.memset (Dest, Value, n);

					reg_write(UINT64, A0, Result);
					break;
				}
			case ucrt_function::STRLEN: 
				{
					CHAR *s = 0;
					reg_read (CHAR*, s, A0);

					SIZE_T Result = Api->typecaster.strlen (s);

					reg_write (SIZE_T, A0, Result);
					break;
				}
			case UCRT_FUNCTION::STRCPY: 
				{
					CHAR *Dest = 0, *Src = 0;

					reg_read (CHAR*, Dest, A0);
					reg_read (CHAR*, Src, A1);

					CHAR *Result = Api->typecaster.strcpy (Dest, Src);

					reg_write (UINT_PTR, A0, Result);
					break;
				}
			case UCRT_FUNCTION::MMAP: 
				{
					LPVOID Addr = 0;
					SIZE_T Len 	= 0;
					DWORD prot 	= 0, Flags = 0;

					reg_read (LPVOID, Addr, A0);
					reg_read (SIZE_T, Len, A1);
					reg_read (DWORD, Prot, A2);
					reg_read (DWORD, Flags, A3);

					LPVOID HostMem = Api->typecaster.mmap (
							nullptr, len, MEM_COMMIT | MEM_RESERVE, LINUX_TO_WIN_PROT (prot));

					if (! MemoryRegister ((UINT_PTR*)&Addr, HostMem, Len)) {
						SetCsrTrap (Vmcs->Hdw.Pc, OutOfMemory, 0, (UINT_PTR)Addr, true);
					}

					reg_write(UINT_PTR, A0, Addr);
					break;
				}
			case UCRT_FUNCTION::MUNMAP: 
				{
					LPVOID Addr = 0;
					SIZE_T Len 	= 0;

					reg_read (LPVOID, Addr, A0);
					reg_read (SIZE_T, Len, A1);

					auto GuestMem 	= (UINT_PTR)Addr;
					LPVOID HostMem 	= MemoryCheck (GuestMem);
					BOOL Unregister = MemoryUnregister (GuestMem);

					INT Result = Api->typecaster.munmap (HostMem, Len, MEM_RELEASE);

					if (! MemoryUnregister ((UINT_PTR)Addr)) {
						SetCsrTrap (Vmcs->Hdw.Pc, OutOfMemory, 0, (UINT_PTR)Addr, true);
					}

					reg_write (INT, A0, ((Result && Unregister) ? 0 : -1));
					break;
				}
			case UCRT_FUNCTION::MPROTECT: 
				{
					LPVOID Addr = 0;
					SIZE_T Len 	= 0;
					DWORD Prot 	= 0, Old = 0;

					reg_read (LPVOID, Addr, A0);
					reg_read (SIZE_T, Len, A1);
					reg_read (DWORD, Prot, A2);

					auto Func = Api->typecaster.mprotect (Addr, Len, Prot, &Old);

					reg_write (INT, A0, Func ? 0 : -1);
					break;
				}
			default: 
				{
					SetCsrTrap (Vmcs->Hdw.Pc, IllegalInstruction, 0, Api->Typenum, true);
				}
		}
	}
}
#endif // RVNI_H
