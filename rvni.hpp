#ifndef RVNI_H
#define RVNI_H
#include <unordered_map>
#include <windows.h>

#include "vmmain.hpp"
#include "vmcommon.hpp"
#include "vmrwx.hpp"

namespace rvm64::rvni {
	// NOTE: this requires C++ stdlib to be statically linked. consider replacing with simple_map::unordered_map.
	_data std::unordered_map<void*, ucrt_wrapper> ucrt_native_table;

	_data ucrt_alias alias_table[] = {
		{ "open",  "_open"  }, { "read",  "_read"  }, { "write", "_write" },
		{ "close", "_close" }, { "exit",  "_exit"  },
	};

	_data ucrt_function unresolved[] = {
		{"_open", ucrt_wrapper::PLT_OPEN}, {"_read", ucrt_wrapper::PLT_READ}, {"_write", ucrt_wrapper::PLT_WRITE}, {"_close", ucrt_wrapper::PLT_CLOSE},
		{"_lseek", ucrt_wrapper::PLT_LSEEK}, {"_stat64", ucrt_wrapper::PLT_STAT64}, {"malloc", ucrt_wrapper::PLT_MALLOC}, {"free", ucrt_wrapper::PLT_FREE},
		{"memcpy", ucrt_wrapper::PLT_MEMCPY}, {"memset", ucrt_wrapper::PLT_MEMSET}, {"strlen", ucrt_wrapper::PLT_STRLEN}, {"strcpy", ucrt_wrapper::PLT_STRCPY},
	};

	_native void* windows_thunk_resolver(const char* sym_name) {
		static HMODULE ucrt = LoadLibraryA("ucrtbase.dll");
		if (!ucrt) {
			CSR_SET_TRAP(nullptr, image_bad_symbol, 0, 0, 1);
		}

		for (auto &i : alias_table) {
			if (strcmp(sym_name, i.original) == 0) {
				sym_name = i.alias;
				break;
			}
		}

		void *proc = (void*)GetProcAddress(ucrt, sym_name);
		if (!proc) {
			CSR_SET_TRAP(nullptr, image_bad_symbol, 0, (uintptr_t)sym_name, 1);
		}

		return proc;
	}

	_native void resolve_ucrt_imports() {
		HMODULE ucrt = LoadLibraryA("ucrtbase.dll");
		if (!ucrt) {
			CSR_SET_TRAP(nullptr, image_bad_symbol, 0, 0, 1);
		}

		for (auto& f : unresolved) {
			void* native = (void*)GetProcAddress(ucrt, f.name);
			if (!native) {
				CSR_SET_TRAP(nullptr, image_bad_symbol, 0, (uintptr_t)f.name, 1);
			}

			ucrt_wrapper wrap = { };
			wrap.address = native;
			wrap.type = f.type;

			switch (wrap.type) {
				case ucrt_wrapper::PLT_OPEN:    wrap.typecaster.open = (decltype(wrap.typecaster.open))native; break;
				case ucrt_wrapper::PLT_READ:    wrap.typecaster.read = (decltype(wrap.typecaster.read))native; break;
				case ucrt_wrapper::PLT_WRITE:   wrap.typecaster.write = (decltype(wrap.typecaster.write))native; break;
				case ucrt_wrapper::PLT_CLOSE:   wrap.typecaster.close = (decltype(wrap.typecaster.close))native; break;
				case ucrt_wrapper::PLT_LSEEK:   wrap.typecaster.lseek = (decltype(wrap.typecaster.lseek))native; break;
				case ucrt_wrapper::PLT_STAT64:  wrap.typecaster.stat64 = (decltype(wrap.typecaster.stat64))native; break;
				case ucrt_wrapper::PLT_MALLOC:  wrap.typecaster.malloc = (decltype(wrap.typecaster.malloc))native; break;
				case ucrt_wrapper::PLT_FREE:    wrap.typecaster.free = (decltype(wrap.typecaster.free))native; break;
				case ucrt_wrapper::PLT_MEMCPY:  wrap.typecaster.memcpy = (decltype(wrap.typecaster.memcpy))native; break;
				case ucrt_wrapper::PLT_MEMSET:  wrap.typecaster.memset = (decltype(wrap.typecaster.memset))native; break;
				case ucrt_wrapper::PLT_STRLEN:  wrap.typecaster.strlen = (decltype(wrap.typecaster.strlen))native; break;
				case ucrt_wrapper::PLT_STRCPY:  wrap.typecaster.strcpy = (decltype(wrap.typecaster.strcpy))native; break;
				default: {
					CSR_SET_TRAP(nullptr, image_bad_symbol, 0, 0, 1);
				}
			}

			ucrt_native_table[native] = wrap;
		}
	}

	_vmcall void vm_native_call() {
		auto it = ucrt_native_table.find((void*)vmcs->pc);
		if (it == ucrt_native_table.end()) {
			CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, vmcs->pc, 1);
		}

		ucrt_wrapper &plt = it->second;
		switch (plt.type) {
			case ucrt_wrapper::PLT_OPEN: {
				char *pathname;
				int flags = 0, mode = 0;

				reg_read(char*, pathname, regenum::a0);
				reg_read(int, flags, regenum::a1);
				reg_read(int, mode, regenum::a2);

				int result = plt.typecaster.open(pathname, flags, mode);
				reg_write(int, regenum::a0, result);
				break;
			}
			case ucrt_wrapper::PLT_READ: {
				int fd = 0;
				void *buf;
				unsigned int count = 0;

				reg_read(int, fd, regenum::a0);
				reg_read(void*, buf, regenum::a1);
				reg_read(unsigned int, count, regenum::a2);

				int result = plt.typecaster.read(fd, buf, count);
				reg_write(int, regenum::a0, result);
				break;
			}
			case ucrt_wrapper::PLT_WRITE: {
				int fd = 0;
				void *buf;
				unsigned int count = 0;

				reg_read(int, fd, regenum::a0);
				reg_read(void*, buf, regenum::a1);
				reg_read(unsigned int, count, regenum::a2);

				int result = plt.typecaster.write(fd, buf, count);
				reg_write(int, regenum::a0, result);
				break;
			}
			case ucrt_wrapper::PLT_CLOSE: {
				int fd = 0;
				reg_read(int, fd, regenum::a0);

				int result = plt.typecaster.close(fd);
				reg_write(int, regenum::a0, result);
				break;
			}
			case ucrt_wrapper::PLT_LSEEK: {
				int fd = 0;
				long offset = 0;
				int whence = 0;

				reg_read(int, fd, regenum::a0);
				reg_read(long, offset, regenum::a1);
				reg_read(int, whence, regenum::a2);

				long result = plt.typecaster.lseek(fd, offset, whence);
				reg_write(long, regenum::a0, result);
				break;
			}
			case ucrt_wrapper::PLT_STAT64: {
				const char *pathname;
				void *statbuf;

				reg_read(const char*, pathname, regenum::a0);
				reg_read(void*, statbuf, regenum::a1);

				int result = plt.typecaster.stat64(pathname, statbuf);
				reg_write(int, regenum::a0, result);
				break;
			}
			case ucrt_wrapper::PLT_MALLOC: {
				size_t size = 0;
				reg_read(size_t, size, regenum::a0);

				void* result = plt.typecaster.malloc(size);
				reg_write(uintptr_t, regenum::a0, result);
				break;
			}
			case ucrt_wrapper::PLT_FREE: {
				void *ptr;
				reg_read(void*, ptr, regenum::a0);

				plt.typecaster.free(ptr);
				break;
			}
			case ucrt_wrapper::PLT_MEMCPY: {
				void *dest, *src;
				size_t n = 0;

				reg_read(void*, dest, regenum::a0);
				reg_read(void*, src, regenum::a1);
				reg_read(size_t, n, regenum::a2);

				void* result = plt.typecaster.memcpy(dest, src, n);
				reg_write(uintptr_t, regenum::a0, result);
				break;
			}
			case ucrt_wrapper::PLT_MEMSET: {
				void *dest;
				int value = 0;
				size_t n = 0;

				reg_read(void*, dest, regenum::a0);
				reg_read(int, value, regenum::a1);
				reg_read(size_t, n, regenum::a2);

				void* result = plt.typecaster.memset(dest, value, n);
				reg_write(uint64_t, regenum::a0, result);
				break;
			}
			case ucrt_wrapper::PLT_STRLEN: {
				char *s;
				reg_read(char*, s, regenum::a0);

				size_t result = plt.typecaster.strlen(s);
				reg_write(size_t, regenum::a0, result);
				break;
			}
			case ucrt_wrapper::PLT_STRCPY: {
				char *dest, *src;

				reg_read(char*, dest, regenum::a0);
				reg_read(char*, src, regenum::a1);

				char* result = plt.typecaster.strcpy(dest, src);
				reg_write(uintptr_t, regenum::a0, result);
				break;
			}
			default: {
				CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, plt.type, 1);
			}
		}

		reg_read(uintptr_t, vmcs->pc, regenum::ra);
		CSR_SET_TRAP(0, environment_branch, 0, 0, 0);
	}
}
#endif // RVNI_H
