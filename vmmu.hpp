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

	_native bool memory_register(uintptr_t guest, void *host, size_t length) {
		if (native_exec_count >= 128 || guest == 0 || (uintptr_t)host == 0) {
			return false;
		}

		for (auto& exec : native_exec_regions) {
			if (exec.guest_addr == 0) {
				exec = { guest, host, length };
				native_exec_count++;
				return true;
			}
		}
		return false;
	}

	_native bool memory_unregister(uintptr_t guest) {
		if (guest == 0) {
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
			return 0;
		}
		for (const auto& entry : native_exec_regions) {
			if (guest >= entry.guest_addr && guest < entry.guest_addr + entry.length) {
				uintptr_t offset = guest - entry.guest_addr;
				return (uint8_t*) entry.host_addr + offset; // risc-v usable address for calculating non-zero offsets (host[n + i])
			}
		}
		return 0;
	}
};
#endif // VMMU_H
