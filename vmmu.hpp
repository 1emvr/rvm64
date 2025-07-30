#ifndef VMMU_H
#define VMMU_H
#include "vmmain.hpp"

namespace rvm64::mmu {
	struct exec_region {
		uintptr_t guest_addr;
		void* host_addr;
		size_t length;
	};

	_data exec_region native_exec_regions[128] = { };
	_data size_t native_exec_count = 0;

	_native bool memory_register(uintptr_t* guest, void *host, size_t length) {
		if (native_exec_count >= 128 || (uintptr_t)host == 0 || guest == nullptr) {
			return false;
		}
		if (*guest == (uintptr_t)-1) { // NOTE: allow the v_program to handle on it's own.
			return true;
		}
		__debugbreak();
		if (*guest == (uintptr_t)0) {
			*guest = (uintptr_t)host;
		}
		for (auto& exec : native_exec_regions) {
			if (exec.guest_addr == 0) {
				exec = { *guest, host, length };
				native_exec_count++;
				return true;
			}
		}
		return false;
	}

	_native bool memory_unregister(uintptr_t guest) {
		if (guest == 0 || native_exec_count == 0) {
			return false;
		}
		for (size_t i = 0; i < native_exec_count; ++i) {
			if (native_exec_regions[i].guest_addr == guest) {
				for (size_t j = i; j < native_exec_count - 1; ++j) {
					native_exec_regions[j] = native_exec_regions[j + 1];
				}

				native_exec_regions[native_exec_count - 1] = { 0, 0, 0 };
				--native_exec_count;
				return true;
			}
		}
		return false;
	}

	_native uint8_t* memory_check(uintptr_t guest) {
		if (guest == 0) {
			return nullptr;
		}
		for (const auto& entry : native_exec_regions) {
			if (guest >= entry.guest_addr && guest < entry.guest_addr + entry.length) {
				uintptr_t offset = guest - entry.guest_addr;
				return (uint8_t*) entry.host_addr + offset; // risc-v usable address for calculating non-zero offsets (host[n + i])
			}
		}
		return nullptr;
	}

#define PROT_READ	0x1		
#define PROT_WRITE	0x2		
#define PROT_EXEC	0x4		
#define PROT_SEM	0x8	

	DWORD translate_linux_prot(DWORD prot) {
		if (prot == 0) {
			return PAGE_NOACCESS;
		}

		bool can_read  = prot & PROT_READ;
		bool can_write = prot & PROT_WRITE;
		bool can_exec  = prot & PROT_EXEC;

		if (can_exec) {
			if (can_write)
				return PAGE_EXECUTE_READWRITE;
			if (can_read)
				return PAGE_EXECUTE_READ;
			return PAGE_EXECUTE;
		} else {
			if (can_write)
				return PAGE_READWRITE;
			if (can_read)
				return PAGE_READONLY;
		}

		return PAGE_NOACCESS;
	}
};
#endif // VMMU_H
