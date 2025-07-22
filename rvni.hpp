#ifndef RVNI_H
#define RVNI_H
#include <unordered_map>
#include <windows.h>

#include "vmmain.hpp"
#include "vmcommon.hpp"
#include "vmrwx.hpp"

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

namespace rvm64::rvni {
	struct ucrt_function {
		void *address;
		const char *name;

		enum {
			OPEN, READ, WRITE, CLOSE, LSEEK, STAT64, MALLOC, FREE,
			MEMCPY, MEMSET, STRLEN, STRCPY, MMAP, MUNMAP, MPROTECT,
			UNKNOWN
		} typenum;

		union {
			int (__cdecl*open)(char *, int, int);
			int (__cdecl*read)(int, void *, unsigned int);
			int (__cdecl*write)(int, void *, unsigned int);
			int (__cdecl*close)(int);
			long (__cdecl*lseek)(int, long, int);
			int (__cdecl*stat64)(const char *, void *);
			void * (__cdecl*malloc)(size_t);
			void (__cdecl*free)(void *);
			void * (__cdecl*memcpy)(void *, void *, size_t);
			void * (__cdecl*memset)(void *, int, size_t);
			size_t (__cdecl*strlen)(char *);
			char * (__cdecl*strcpy)(char *, char *);
			VOID * (__stdcall*mmap)(LPVOID, SIZE_T, DWORD, DWORD); // aliased to VirtualAlloc
			BOOL (__stdcall*munmap)(LPVOID, SIZE_T, DWORD); // aliased to VirtualFree
			BOOL (__stdcall*mprotect)(LPVOID, SIZE_T, DWORD, PDWORD); // aliased to VirtualProtect
		} typecaster;
	};

	_data ucrt_function ucrt_function_table[] = {
		{ .address = 0, .name = C_OPEN, 	.typenum = ucrt_function::OPEN		}, 
		{ .address = 0, .name = C_READ, 	.typenum = ucrt_function::READ		}, 
		{ .address = 0, .name = C_WRITE, 	.typenum = ucrt_function::WRITE 	}, 
		{ .address = 0, .name = C_CLOSE, 	.typenum = ucrt_function::CLOSE 	},
		{ .address = 0, .name = C_LSEEK, 	.typenum = ucrt_function::LSEEK 	}, 
		{ .address = 0, .name = C_STAT64, 	.typenum = ucrt_function::STAT64 	}, 
		{ .address = 0, .name = C_MALLOC, 	.typenum = ucrt_function::MALLOC 	}, 
		{ .address = 0, .name = C_FREE, 	.typenum = ucrt_function::FREE 		},
		{ .address = 0, .name = C_MEMCPY, 	.typenum = ucrt_function::MEMCPY 	}, 
		{ .address = 0, .name = C_MEMSET, 	.typenum = ucrt_function::MEMSET 	}, 
		{ .address = 0, .name = C_STRLEN, 	.typenum = ucrt_function::STRLEN 	}, 
		{ .address = 0, .name = C_STRCPY, 	.typenum = ucrt_function::STRCPY 	},
		{ .address = 0, .name = C_MMAP, 	.typenum = ucrt_function::MMAP 		}, 
		{ .address = 0, .name = C_MUNMAP, 	.typenum = ucrt_function::MUNMAP 	}, 
		{ .address = 0, .name = C_MPROTECT, .typenum = ucrt_function::MPROTECT 	},
	};

	struct ucrt_alias {
		const char *original;
		const char *alias;
	};
	_data ucrt_alias alias_table[] = {
		{ "open",  "_open"  }, { "read",  "_read"  }, { "write", "_write" }, { "close", "_close" }, { "exit",  "_exit"  }, 
		{ "mmap", "VirtualAlloc" }, { "munmap", "VirtualFree" }, { "mprotect", "VirtualProtect" }, 
	};

	_native void *resolve_ucrt_import(const char *sym_name) {
		static HMODULE ucrt = LoadLibraryA("ucrtbase.dll");
		static HMODULE kern32 = LoadLibraryA("kernel32.dll");

		if (!ucrt || !kern32) {
			CSR_SET_TRAP(nullptr, image_bad_symbol, 0, 0, 1);
		}

		const char *alias_name = sym_name;

		for (auto& i : alias_table) {
			if (strcmp(sym_name, i.original) == 0) {
				alias_name = (const char*)i.alias;
				break;
			}
		}

		void* native = (void*)GetProcAddress(ucrt, alias_name);
		if (!native) {
			if (!(native = (void*)GetProcAddress(kern32, alias_name))) {
				CSR_SET_TRAP(nullptr, image_bad_symbol, 0, (uintptr_t)alias_name, 1);
			}
		}

		for (auto& f : ucrt_function_table) {
			if (strcmp(sym_name, f.name) == 0) {
				f.address = native;
				 
				switch (f.typenum) {
					case ucrt_function::OPEN:   	f.typecaster.open 		= (decltype(f.typecaster.open))native; break;
					case ucrt_function::READ:   	f.typecaster.read 		= (decltype(f.typecaster.read))native; break;
					case ucrt_function::WRITE:  	f.typecaster.write		= (decltype(f.typecaster.write))native; break;
					case ucrt_function::CLOSE:  	f.typecaster.close 		= (decltype(f.typecaster.close))native; break;
					case ucrt_function::LSEEK:  	f.typecaster.lseek 		= (decltype(f.typecaster.lseek))native; break;
					case ucrt_function::STAT64: 	f.typecaster.stat64 	= (decltype(f.typecaster.stat64))native; break;
					case ucrt_function::MALLOC: 	f.typecaster.malloc 	= (decltype(f.typecaster.malloc))native; break;
					case ucrt_function::FREE:   	f.typecaster.free 		= (decltype(f.typecaster.free))native; break;
					case ucrt_function::MEMCPY: 	f.typecaster.memcpy 	= (decltype(f.typecaster.memcpy))native; break;
					case ucrt_function::MEMSET: 	f.typecaster.memset 	= (decltype(f.typecaster.memset))native; break;
					case ucrt_function::STRLEN: 	f.typecaster.strlen 	= (decltype(f.typecaster.strlen))native; break;
					case ucrt_function::STRCPY: 	f.typecaster.strcpy 	= (decltype(f.typecaster.strcpy))native; break;
					case ucrt_function::MMAP: 		f.typecaster.mmap 		= (decltype(f.typecaster.mmap))native; break;
					case ucrt_function::MUNMAP:		f.typecaster.munmap 	= (decltype(f.typecaster.munmap))native; break;
					case ucrt_function::MPROTECT:	f.typecaster.mprotect 	= (decltype(f.typecaster.mprotect))native; break;
					default:  CSR_SET_TRAP(nullptr, image_bad_symbol, 0, 0, 1);
				}
				break;
			}
		}

		return native;
	}

	_vmcall void vm_native_call() {
		ucrt_function *api = nullptr;

		for (auto &f : ucrt_function_table) {
			if (vmcs->pc == (uintptr_t)f.address) {
				api = &f;
				break;
			}
		}
		if (!api) {
			CSR_SET_TRAP(vmcs->pc, image_bad_symbol, 0, vmcs->pc, 1);
		}

		switch (api->typenum) {
			case ucrt_function::OPEN: 
			{
				char *pathname;
				int flags = 0, mode = 0;

				reg_read(char*, pathname, regenum::a0);
				reg_read(int, flags, regenum::a1);
				reg_read(int, mode, regenum::a2);

				int result = api->typecaster.open(pathname, flags, mode);
				reg_write(int, regenum::a0, result);
				break;
			}
			case ucrt_function::READ: 
			{
				int fd = 0;
				void *buf;
				unsigned int count = 0;

				reg_read(int, fd, regenum::a0);
				reg_read(void*, buf, regenum::a1);
				reg_read(unsigned int, count, regenum::a2);

				int result = api->typecaster.read(fd, buf, count);
				reg_write(int, regenum::a0, result);
				break;
			}
			case ucrt_function::WRITE: 
			{
				int fd = 0;
				void *buf;
				unsigned int count = 0;

				reg_read(int, fd, regenum::a0);
				reg_read(void*, buf, regenum::a1);
				reg_read(unsigned int, count, regenum::a2);

				int result = api->typecaster.write(fd, buf, count);
				reg_write(int, regenum::a0, result);
				break;
			}
			case ucrt_function::CLOSE: 
			{
				int fd = 0;
				reg_read(int, fd, regenum::a0);

				int result = api->typecaster.close(fd);
				reg_write(int, regenum::a0, result);
				break;
			}
			case ucrt_function::LSEEK: 
			{
				int fd = 0;
				long offset = 0;
				int whence = 0;

				reg_read(int, fd, regenum::a0);
				reg_read(long, offset, regenum::a1);
				reg_read(int, whence, regenum::a2);

				long result = api->typecaster.lseek(fd, offset, whence);
				reg_write(long, regenum::a0, result);
				break;
			}
			case ucrt_function::STAT64: 
			{
				const char *pathname;
				void *statbuf;

				reg_read(const char*, pathname, regenum::a0);
				reg_read(void*, statbuf, regenum::a1);

				int result = api->typecaster.stat64(pathname, statbuf);
				reg_write(int, regenum::a0, result);
				break;
			}
			case ucrt_function::MALLOC: 
			{
				size_t size = 0;
				reg_read(size_t, size, regenum::a0);

				void* result = api->typecaster.malloc(size);
				reg_write(uintptr_t, regenum::a0, result);
				break;
			}
			case ucrt_function::FREE: 
			{
				void *ptr;
				reg_read(void*, ptr, regenum::a0);

				api->typecaster.free(ptr);
				reg_write(uintptr_t, regenum::a0, 0);
				break;
			}
			case ucrt_function::MEMCPY: 
			{
				void *dest, *src;
				size_t n = 0;

				reg_read(void*, dest, regenum::a0);
				reg_read(void*, src, regenum::a1);
				reg_read(size_t, n, regenum::a2);

				void* result = api->typecaster.memcpy(dest, src, n);
				reg_write(uintptr_t, regenum::a0, result);
				break;
			}
			case ucrt_function::MEMSET: 
			{
				void *dest;
				int value = 0;
				size_t n = 0;

				reg_read(void*, dest, regenum::a0);
				reg_read(int, value, regenum::a1);
				reg_read(size_t, n, regenum::a2);

				void* result = api->typecaster.memset(dest, value, n);
				reg_write(uint64_t, regenum::a0, result);
				break;
			}
			case ucrt_function::STRLEN: 
			{
				char *s;
				reg_read(char*, s, regenum::a0);

				size_t result = api->typecaster.strlen(s);
				reg_write(size_t, regenum::a0, result);
				break;
			}
			case ucrt_function::STRCPY: 
			{
				char *dest, *src;

				reg_read(char*, dest, regenum::a0);
				reg_read(char*, src, regenum::a1);

				char* result = api->typecaster.strcpy(dest, src);
				reg_write(uintptr_t, regenum::a0, result);
				break;
			}
			case ucrt_function::MMAP: 
			{
				void *addr;
				size_t len;
				DWORD prot, flags;

				reg_read(void*, addr, regenum::a0);
				reg_read(size_t, len, regenum::a1);
				reg_read(DWORD, prot, regenum::a2);
				reg_read(DWORD, flags, regenum::a3);

				void *guest_mem = addr;
				void *host_mem = api->typecaster.mmap(0, len, prot, flags);

				if (!host_mem) {
					reg_write(int, regenum::a0, -1);
					CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, guest_mem, 1);
				} 
				if (!rvm64::mmu::memory_register(guest_mem, host_mem, len)) {
					reg_write(int, regenum::a0, -1);
					CSR_SET_TRAP(vmcs->pc, out_of_memory, 0, guest_mem, 1);
				}

				reg_write(uintptr_t, regenum::a0, guest_mem);
				break;
			}
			case ucrt_function::MUNMAP: 
			{
				void *addr;
				size_t len;

				reg_read(void*, addr, regenum::a0);
				reg_read(size_t, len, regenum::a1);

				void *guest_mem = addr;
				void* host_mem = rvm64::mmu::memory_check(guest_mem);

				if (!host_mem) {
					reg_write(int, regenum::a0, -1);
					CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, guest_mem, 1);
				} 

				rvm64::mmu::memory_unregister(guest_mem);
				int result = api->typecaster.munmap(host_mem, len);

				reg_write(int, regenum::a0, result ? 0 : -1);
				break;
			}
			case ucrt_function::MPROTECT: 
			{
				void *addr;
				size_t len;
				DWORD prot = 0, old = 0;

				reg_read(void*, addr, regenum::a0);
				reg_read(size_t, len, regenum::a1);
				reg_read(DWORD, prot, regenum::a2);

				auto func = (api->typecaster.mprotect)(addr, len, prot, &old);
				reg_write(int, regenum::a0, func ? 0 : -1);
				break;
			}
			default: {
				CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, api->typenum, 1);
			}
		}
	}
}
#endif // RVNI_H
