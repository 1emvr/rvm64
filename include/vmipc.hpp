#ifndef HYPRIPC_HPP
#define HYPRIPC_HPP

#include "vmmain.hpp"
#include "vmmem.hpp"

namespace rvm64::ipc {
	void vm_destroy_channel() {
		if (!vmcs->channel) {
			return;
		}
		if (vmcs->channel->view.buffer) {
			VirtualFree((LPVOID)vmcs->channel->view.buffer, 0, MEM_FREE);
			vmcs->channel->view.buffer = 0;
			vmcs->channel->view.size = 0;
		}

		VirtualFree((LPVOID)vmcs->channel, 0, MEM_RELEASE);
		vmcs->channel = nullptr;
	}

	void vm_create_channel(uint64_t magic1, uint64_t magic2) {
		HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
		HMODULE hmodule = GetModuleHandle(0);

		vmcs->channel = (vm_channel*)rvm64::memory::allocate_2GB_range(hprocess, (uintptr_t)hmodule, PAGE_READWRITE, sizeof(vm_channel));
		if (!vmcs->channel) {
		    CSR_SET_TRAP(nullptr, GetLastError(), 0, 0, 1);
		}

		// vm ipc channel starts by copying it's own pointers for the supervisor to use
		vmcs->channel->self = (uint64_t)vmcs->channel;
		vmcs->channel->vmcs = (uint64_t)vmcs;

		vmcs->channel->magic1 = magic1;
		vmcs->channel->magic2 = magic2;

		vmcs->channel->view.size = CHANNEL_BUFFER_SIZE;
		vmcs->channel->view.buffer = (uint64_t)rvm64::memory::allocate_2GB_range(hprocess, (uintptr_t)hmodule, PAGE_READWRITE, CHANNEL_BUFFER_SIZE); 

		if (!vmcs->channel->view.buffer) {
			CSR_SET_TRAP(vmcs->pc, GetLastError(), 0, 0, 1);
		}
	}

	bool read_channel_buffer(uintptr_t data, uintptr_t offset, size_t size) {
		if (!data || offset > CHANNEL_BUFFER_SIZE || size > CHANNEL_BUFFER_SIZE - offset) {
			return false;
		}
		if (!vmcs->channel || !vmcs->channel->view.buffer) {
			CSR_SET_TRAP(vmcs->pc, load_access_fault, 0, 0, 1);
		}
		if (!vmcs->channel->ready) {
			return false;
		}

		memcpy((uint8_t*)data, (uint8_t*)(vmcs->channel->view.buffer + offset), size);
		vmcs->channel->ready = 0;

		return true;
	}

	bool write_channel_buffer(const uintptr_t data, uintptr_t offset, size_t size) {
		if (!data || offset > CHANNEL_BUFFER_SIZE || size > CHANNEL_BUFFER_SIZE - offset) {
			return false;
		}
		if (!vmcs->channel || !vmcs->channel->view.buffer) {
			CSR_SET_TRAP(vmcs->pc, store_amo_access_fault, 0, 0, 1);
		}

		memcpy((uint8_t*)(vmcs->channel->view.buffer + offset), (uint8_t*)data, size);
		vmcs->channel->view.write_size = (uint64_t)size;
		vmcs->channel->ready = 1;

		return true;
	}
}
#endif // HYPRIPC_HPP
