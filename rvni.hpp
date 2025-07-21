#ifndef RVNI_H
#define RVNI_H
#include <unordered_map>
#include <windows.h>

#include "vmmain.hpp"
#include "vmcommon.hpp"
#include "vmrwx.hpp"

namespace rvm64::rvni {
	struct ucrt_alias {
		const char *original;
		const char *alias;
	};

	struct ucrt_function {
		void *address;
		char *name;

		typedef enum {
			OPEN, READ, WRITE, CLOSE, LSEEK, STAT64, MALLOC, FREE,
			MEMCPY, MEMSET, STRLEN, STRCPY, MMAP, MUNMAP, MPROTECT,
			UNKNOWN
		} typenum;

		typedef union {
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

	_data ucrt_alias alias_table[] = {
		{ "open",  "_open"  }, { "read",  "_read"  }, { "write", "_write" }, { "close", "_close" }, { "exit",  "_exit"  }, 
		{ "mmap", "VirtualAlloc" }, { "munmap", "VirtualFree" }, { "mprotect", "VirtualProtect" }, 
	};

	_data ucrt_function ucrt_native_table[] = {
		{ .address = 0, .name = "_open", 	.typenum = ucrt_function::OPEN		}, 
		{ .address = 0, .name = "_read", 	.typenum = ucrt_function::READ		}, 
		{ .address = 0, .name = "_write", 	.typenum = ucrt_function::WRITE 	}, 
		{ .address = 0, .name = "_close", 	.typenum = ucrt_function::CLOSE 	},
		{ .address = 0, .name = "_lseek", 	.typenum = ucrt_function::LSEEK 	}, 
		{ .address = 0, .name = "_stat64", 	.typenum = ucrt_function::STAT64 	}, 
		{ .address = 0, .name = "malloc", 	.typenum = ucrt_function::MALLOC 	}, 
		{ .address = 0, .name = "free", 	.typenum = ucrt_function::FREE 		},
		{ .address = 0, .name = "memcpy", 	.typenum = ucrt_function::MEMCPY 	}, 
		{ .address = 0, .name = "memset", 	.typenum = ucrt_function::MEMSET 	}, 
		{ .address = 0, .name = "strlen", 	.typenum = ucrt_function::STRLEN 	}, 
		{ .address = 0, .name = "strcpy", 	.typenum = ucrt_function::STRCPY 	},
		{ .address = 0, .name = "mmap", 	.typenum = ucrt_function::MMAP 		}, 
		{ .address = 0, .name = "munmap", 	.typenum = ucrt_function::MUNMAP 	}, 
		{ .address = 0, .name = "mprotect", .typenum = ucrt_function::MPROTECT 	},
	};

	_native void *resolve_ucrt_import(char *sym_name) {
		static HMODULE ucrt = LoadLibraryA("ucrtbase.dll");
		static HMODULE kern32 = LoadLibraryA("kernel32.dll");

		if (!ucrt || !kern32) {
			CSR_SET_TRAP(nullptr, image_bad_symbol, 0, 0, 1);
		}

		char *orig_name = nullptr;

		for (auto& i : alias_table) {
			if (strcmp(i.original, sym_name) == 0) {
				orig_name = i.original;
				sym_name = i.alias;
				break;
			}
		}
		if (!orig_name) {
			CSR_SET_TRAP(nullptr, image_bad_symbol, 0, (uintptr_t)&sym_name, 1);
		}

		void* native = (void*)GetProcAddress(ucrt, sym_name);
		if (!native) {
			if (!(native = (void*)GetProcAddress(kern32, sym_name))) {
				CSR_SET_TRAP(nullptr, image_bad_symbol, 0, (uintptr_t)&sym_name, 1);
			}
		}

		// function found, search the ucrt_native_table for matching name and set the address/typecaster
		for (auto& f : ucrt_native_table) {
			if (strcmp(f.name, orig_name) == 0) {
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
			}
		}

		return native;
	}

	_vmcall void vm_native_call() {
		void *address = nullptr;
		ucrt_function api = { };

		for (auto &f : ucrt_native_table) {
			if (vmcs->pc == f.address) {
				api = f;
				break;
			}
		}
		if (!api.address) {
			CSR_SET_TRAP(vmcs->pc, image_bad_symbol, 0, vmcs->pc, 1);
		}

		switch (api.typenum) {
			case ucrt_function::OPEN: {
				char *pathname;
				int flags = 0, mode = 0;

				reg_read(char*, pathname, regenum::a0);
				reg_read(int, flags, regenum::a1);
				reg_read(int, mode, regenum::a2);

				int result = api.typecaster.open(pathname, flags, mode);
				reg_write(int, regenum::a0, result);
				break;
			}
			case ucrt_function::READ: {
				int fd = 0;
				void *buf;
				unsigned int count = 0;

				reg_read(int, fd, regenum::a0);
				reg_read(void*, buf, regenum::a1);
				reg_read(unsigned int, count, regenum::a2);

				int result = api.typecaster.read(fd, buf, count);
				reg_write(int, regenum::a0, result);
				break;
			}
			case ucrt_function::WRITE: {
				int fd = 0;
				void *buf;
				unsigned int count = 0;

				reg_read(int, fd, regenum::a0);
				reg_read(void*, buf, regenum::a1);
				reg_read(unsigned int, count, regenum::a2);

				int result = api.typecaster.write(fd, buf, count);
				reg_write(int, regenum::a0, result);
				break;
			}
			case ucrt_function::CLOSE: {
				int fd = 0;
				reg_read(int, fd, regenum::a0);

				int result = api.typecaster.close(fd);
				reg_write(int, regenum::a0, result);
				break;
			}
			case ucrt_function::LSEEK: {
				int fd = 0;
				long offset = 0;
				int whence = 0;

				reg_read(int, fd, regenum::a0);
				reg_read(long, offset, regenum::a1);
				reg_read(int, whence, regenum::a2);

				long result = api.typecaster.lseek(fd, offset, whence);
				reg_write(long, regenum::a0, result);
				break;
			}
			case ucrt_function::STAT64: {
				const char *pathname;
				void *statbuf;

				reg_read(const char*, pathname, regenum::a0);
				reg_read(void*, statbuf, regenum::a1);

				int result = api.typecaster.stat64(pathname, statbuf);
				reg_write(int, regenum::a0, result);
				break;
			}
			case ucrt_function::MALLOC: {
				size_t size = 0;
				reg_read(size_t, size, regenum::a0);

				void* result = api.typecaster.malloc(size);
				reg_write(uintptr_t, regenum::a0, result);
				break;
			}
			case ucrt_function::FREE: {
				void *ptr;
				reg_read(void*, ptr, regenum::a0);

				api.typecaster.free(ptr);
				break;
			}
			case ucrt_function::MEMCPY: {
				void *dest, *src;
				size_t n = 0;

				reg_read(void*, dest, regenum::a0);
				reg_read(void*, src, regenum::a1);
				reg_read(size_t, n, regenum::a2);

				void* result = api.typecaster.memcpy(dest, src, n);
				reg_write(uintptr_t, regenum::a0, result);
				break;
			}
			case ucrt_function::MEMSET: {
				void *dest;
				int value = 0;
				size_t n = 0;

				reg_read(void*, dest, regenum::a0);
				reg_read(int, value, regenum::a1);
				reg_read(size_t, n, regenum::a2);

				void* result = api.typecaster.memset(dest, value, n);
				reg_write(uint64_t, regenum::a0, result);
				break;
			}
			case ucrt_function::STRLEN: {
				char *s;
				reg_read(char*, s, regenum::a0);

				size_t result = api.typecaster.strlen(s);
				reg_write(size_t, regenum::a0, result);
				break;
			}
			case ucrt_function::STRCPY: {
				char *dest, *src;

				reg_read(char*, dest, regenum::a0);
				reg_read(char*, src, regenum::a1);

				char* result = api.typecaster.strcpy(dest, src);
				reg_write(uintptr_t, regenum::a0, result);
				break;
			}
			default: {
				CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, plt.type, 1);
			}
		}
	}
}
#endif // RVNI_H
