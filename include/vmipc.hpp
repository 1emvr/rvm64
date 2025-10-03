#ifndef HYPRIPC_HPP
#define HYPRIPC_HPP

#include "vmmain.hpp"
#include "vmmem.hpp"

namespace rvm64::ipc {
	void vm_destroy_channel() {
		if (vmcs->channel.view.buffer) {
			VirtualFree((LPVOID)vmcs->channel.view.buffer, 0, MEM_RELEASE);
			vmcs->channel.view.buffer = 0;
			vmcs->channel.view.write_size = 0;
			vmcs->channel.view.size = 0;

			vmcs->channel.ready = 0;
			vmcs->channel.error = 0;

			vmcs->channel.size_ptr = 0;
			vmcs->channel.ready_ptr = 0;
			vmcs->channel.error_ptr = 0;
			vmcs->channel.write_size_ptr = 0;

			vmcs->channel.magic1 = 0;
			vmcs->channel.magic2 = 0;
			vmcs->channel.self   = 0;
		}
	}

	void vm_create_channel(uint64_t magic1, uint64_t magic2) {
		vmcs->channel.view.size   = CHANNEL_BUFFER_SIZE;
		vmcs->channel.view.buffer = (uint64_t)VirtualAlloc(nullptr, CHANNEL_BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!vmcs->channel.view.buffer) {
			CSR_SET_TRAP(vmcs->pc, GetLastError(), 0, 0, 1);
			return;
		}

		vmcs->channel.view.write_size = 0;
		vmcs->channel.ready = 0;
		vmcs->channel.error = 0;

		vmcs->channel.self   	= (uint64_t)&vmcs->channel;
		vmcs->channel.vmcs_ptr 	= (uint64_t)&vmcs->channel;

		vmcs->channel.magic1 	= magic1;
		vmcs->channel.magic2 	= magic2;

		vmcs->channel.ready_ptr      = (uint64_t)&vmcs->channel.ready;
		vmcs->channel.size_ptr 		 = (uint64_t)&vmcs->channel.view.size;
		vmcs->channel.write_size_ptr = (uint64_t)&vmcs->channel.view.write_size;

		vmcs->channel.vpc_ptr		= (uint64_t)&vmcs->pc;
		vmcs->channel.vstack_ptr 	= (uint64_t)&vmcs->vstack;
		vmcs->channel.vregs_ptr		= (uint64_t)&vmcs->vregs;
	}

	bool get_channel_ready(HANDLE hprocess, vm_channel* channel) {
		uint64_t v = 0;
		if (!rvm64::memory::read_process_memory(hprocess, (uintptr_t)channel->ready_ptr, (uint8_t*)&v, sizeof(v))) {
			printf("[ERR] read channel->ready failed.\n");
			return false;
		}
		return v == 1ULL;
	}

	bool set_channel_ready(HANDLE hprocess, vm_channel* channel, uint64_t ready) {
		size_t write = 0;
		if (!rvm64::memory::write_process_memory(hprocess, (uintptr_t)channel->ready_ptr, (uint8_t*)&ready, sizeof(ready), &write)) {
			printf("[ERR] write channel->ready failed.\n");
			return false;
		}
		return true;
	}

	uint64_t get_channel_write_size(HANDLE hprocess, vm_channel* channel) {
		uint64_t v = 0;
		if (!rvm64::memory::read_process_memory(hprocess, (uintptr_t)channel->write_size_ptr, (uint8_t*)&v, sizeof(v))) {
			printf("[ERR] read channel->view.write_size failed.\n");
			return 0;
		}
		return v;
	}

	bool set_channel_write_size(HANDLE hprocess, vm_channel* channel, uint64_t nbytes) {
		size_t write = 0;
		if (!rvm64::memory::write_process_memory(hprocess, (uintptr_t)channel->write_size_ptr, (uint8_t*)&nbytes, sizeof(nbytes), &write)) {
			printf("[ERR] write channel->view.write_size failed.\n");
			return false;
		}
		return true;
	}

	uint64_t get_channel_error(HANDLE hprocess, vm_channel* channel) {
		uint64_t v = 0;
		if (!rvm64::memory::read_process_memory(hprocess, (uintptr_t)channel->error_ptr, (uint8_t*)&v, sizeof(v))) {
			printf("[ERR] read channel->error failed.\n");
			return UINT64_MAX; // or 0; but make it explicit
		}
		return v;
	}

	bool set_channel_error(HANDLE hprocess, vm_channel* channel, uint64_t code) {
		size_t write = 0;
		if (!rvm64::memory::write_process_memory(hprocess, (uintptr_t)channel->error_ptr, (uint8_t*)&code, sizeof(code), &write)) {
			printf("[ERR] write channel->error failed.\n");
			return false;
		}
		return true;
	}
}
#endif // HYPRIPC_HPP
