#ifndef HYPRIPC_HPP
#define HYPRIPC_HPP

#include "vmmain.hpp"
#include "vmmem.hpp"

namespace rvm64::ipc {
	bool get_vmcs_ready(HANDLE hprocess, vmcs_t* vmcs) {
		uint64_t v = 0;
		if (!rvm64::memory::read_process_memory(hprocess, (uintptr_t)vmcs->ready_ptr, (uint8_t*)&v, sizeof(v))) {
			printf("[ERR] read channel->ready failed.\n");
			return false;
		}
		return v == 1ULL;
	}

	bool set_vmcs_ready(HANDLE hprocess, vmcs_t* vmcs, uint64_t ready) {
		size_t write = 0;
		if (!rvm64::memory::write_process_memory(hprocess, (uintptr_t)vmcs->ready_ptr, (uint8_t*)&ready, sizeof(ready), &write)) {
			printf("[ERR] write channel->ready failed.\n");
			return false;
		}
		return true;
	}

	uint64_t get_vmcs_write_size(HANDLE hprocess, vmcs_t* vmcs) {
		uint64_t v = 0;
		if (!rvm64::memory::read_process_memory(hprocess, (uintptr_t)vmcs->write_size_ptr, (uint8_t*)&v, sizeof(v))) {
			printf("[ERR] read channel->view.write_size failed.\n");
			return 0;
		}
		return v;
	}

	bool set_vmcs_write_size(HANDLE hprocess, vmcs_t* vmcs, uint64_t nbytes) {
		size_t write = 0;
		if (!rvm64::memory::write_process_memory(hprocess, (uintptr_t)vmcs->write_size_ptr, (uint8_t*)&nbytes, sizeof(nbytes), &write)) {
			printf("[ERR] write channel->view.write_size failed.\n");
			return false;
		}
		return true;
	}
}
#endif // HYPRIPC_HPP
