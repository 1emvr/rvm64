#ifndef HYPRIPC_HPP
#define HYPRIPC_HPP

#include "vmmain.hpp"
#include "vmmem.hpp"

namespace rvm64::ipc {
	void vm_destroy_channel() {
		if (vmcs->proc.buffer) {
			VirtualFree((LPVOID)vmcs->proc.buffer, 0, MEM_RELEASE);
			vmcs->proc.buffer = 0;
		}

		vmcs->proc.size = 0;
		vmcs->proc.write_size = 0;

		vmcs->magic1 = 0; vmcs->magic2 = 0;
	}

	void vm_create_channel(uint64_t magic1, uint64_t magic2) {
		vmcs->ptrs.self   = (uint64_t)vmcs;
		vmcs->proc.buffer = (uint64_t)VirtualAlloc(nullptr, PROCESS_BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!vmcs->proc.buffer) {
			CSR_SET_TRAP(vmcs->hdw.pc, GetLastError(), 0, 0, 1);
			return;
		}

		vmcs->proc.size   			= PROCESS_BUFFER_SIZE;
		vmcs->proc.write_size 		= (uint64_t)0;
		vmcs->proc.ready 			= (uint64_t)0;

		vmcs->ptrs.size_ptr 		= (uint64_t)&vmcs->proc.size;
		vmcs->ptrs.write_size_ptr 	= (uint64_t)&vmcs->proc.write_size;
		vmcs->ptrs.ready_ptr 		= (uint64_t)&vmcs->proc.ready;

		vmcs->magic1 = magic1;
		vmcs->magic2 = magic2;
	}

	bool get_vmcs_ready(HANDLE hprocess, vmcs_t* vmcs) {
		uint64_t v = 0;
		if (!rvm64::memory::read_process_memory(hprocess, (uintptr_t)vmcs->ptrs.ready_ptr, (uint8_t*)&v, sizeof(v))) {
			printf("[ERR] read channel->ready failed.\n");
			return false;
		}
		return v == 1ULL;
	}

	bool set_vmcs_ready(HANDLE hprocess, vmcs_t* vmcs, uint64_t ready) {
		size_t write = 0;
		if (!rvm64::memory::write_process_memory(hprocess, (uintptr_t)vmcs->ptrs.ready_ptr, (uint8_t*)&ready, sizeof(ready), &write)) {
			printf("[ERR] write channel->ready failed.\n");
			return false;
		}
		return true;
	}

	uint64_t get_vmcs_write_size(HANDLE hprocess, vmcs_t* vmcs) {
		uint64_t v = 0;
		if (!rvm64::memory::read_process_memory(hprocess, (uintptr_t)vmcs->ptrs.write_size_ptr, (uint8_t*)&v, sizeof(v))) {
			printf("[ERR] read channel->view.write_size failed.\n");
			return 0;
		}
		return v;
	}

	bool set_vmcs_write_size(HANDLE hprocess, vmcs_t* vmcs, uint64_t nbytes) {
		size_t write = 0;
		if (!rvm64::memory::write_process_memory(hprocess, (uintptr_t)vmcs->ptrs.write_size_ptr, (uint8_t*)&nbytes, sizeof(nbytes), &write)) {
			printf("[ERR] write channel->view.write_size failed.\n");
			return false;
		}
		return true;
	}
}
#endif // HYPRIPC_HPP
