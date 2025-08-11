#ifndef VMMU_H
#define VMMU_H
#include "../include/vmmain.hpp"

#define PROT_READ	0x1		
#define PROT_WRITE	0x2		
#define PROT_EXEC	0x4		
#define PROT_SEM	0x8	

namespace rvm64::mmu {
	struct exec_region {
		uintptr_t guest_addr;
		void* host_addr;
		size_t length;
	};

	_data exec_region page_table[128] = { };
	_data static size_t page_count = 0;

	_native bool memory_register(uintptr_t* guest, void *host, size_t length) {
		if (page_count >= 128 || (uintptr_t)host == 0 || guest == nullptr) {
			return false;
		}
		if (*guest == (uintptr_t)0) {
			*guest = (uintptr_t)host;
		}
		for (auto& entry : page_table) {
			if (entry.guest_addr == 0) {
				entry = { *guest, host, length };
				page_count++;
				return true;
			}
		}
		return false;
	}

	_native bool memory_unregister(uintptr_t guest) {
		if (guest == 0 || page_count == 0) {
			return false;
		}
		for (size_t i = 0; i < page_count; ++i) {
			if (page_table[i].guest_addr == guest) {
				for (size_t j = i; j < page_count - 1; ++j) {
					page_table[j] = page_table[j + 1];
				}

				page_table[page_count - 1] = { 0, 0, 0 };
				--page_count;
				return true;
			}
		}
		return false;
	}

	_native uint8_t* memory_check(uintptr_t guest) {
		if (guest == 0) {
			return nullptr;
		}
		for (const auto& entry : page_table) {
			if (guest >= entry.guest_addr && guest < entry.guest_addr + entry.length) {
				uintptr_t offset = guest - entry.guest_addr;
				return (uint8_t*) entry.host_addr + offset; // risc-v usable address for calculating non-zero offsets (host[n + i])
			}
		}
		return nullptr;
	}

	DWORD translate_linux_prot(uint32_t prot) {
		if (prot == 0) return PAGE_NOACCESS;

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
