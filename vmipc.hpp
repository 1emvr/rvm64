#ifndef HYPRIPC_HPP
#define HYPRIPC_HPP

#include "vmmain.hpp"
#include "vmscan.hpp"
#include "vmmem.hpp"

namespace rvm64::ipc {
	void vm_destroy_channel() {
		if (!vmcs->channel) {
			return;
		}
		if (vmcs->channel->view.buffer) {
			VirtualFree(vmcs->channel->view.buffer, 0, MEM_FREE);
			vmcs->channel->view.buffer = nullptr;
			vmcs->channel->view.size = 0;
		}

		HeapFree(GetProcessHeap(), 0, vmcs->channel);
		vmcs->channel = nullptr;
	}

	void vm_create_channel() {
		HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
		HMODULE hmodule = GetModuleHandle(0);

		vmcs->channel = (vm_channel*)rvm64::memory::allocate_2GB_range(hprocess, PAGE_READWRITE, hmodule, sizeof(vm_channel));
		if (!vmcs->channel) {
		    CSR_SET_TRAP(nullptr, GetLastError(), 0, 0, 1);
		}

		vmcs->channel.self = vmcs->channel;
		vmcs->channel->ipc.vmcs = vmcs;
		vmcs->channel.header_size = (sizeof(uint64_t) * 4) + sizeof(LPVOID);

		vmcs->channel.magic1 = VM_MAGIC1;
		vmcs->channel.magic2 = VM_MAGIC2;

		vmcs->channel->view.size = CHANNEL_BUFFER_SIZE;
		vmcs->channel->view.buffer = rvm64::memory::allocate_2GB_range(hprocess, PAGE_READWRITE, hmodule, CHANNEL_BUFFER_SIZE); 

		if (!vmcs->channel->view.buffer) {
			destroy_channel();
			CSR_SET_TRAP(vmcs->pc, GetLastError(), 0, 0, 1);
		}
	}

	bool read_channel_buffer(uint8_t* data, uintptr_t offset, size_t size) {
		if (!data || offset > CHANNEL_BUFFER_SIZE || size > CHANNEL_BUFFER_SIZE - offset) {
			return false;
		}
		if (!vmcs->channel || !vmcs->channel.buffer) {
			CSR_SET_TRAP(vmcs->pc, load_access_fault, 0, 0, 1);
		}
		if (!vmcs->channel.ready) {
			return false;
		}

		memcpy(data, (uint8_t*)(vmcs->channel->view.buffer + offset), size);
		vmcs->channel.ready = 0;

		return true;
	}

	bool write_channel_buffer(const uint8_t* data, uintptr_t offset, size_t size) {
		if (!data || offset > CHANNEL_BUFFER_SIZE || size > CHANNEL_BUFFER_SIZE - offset) {
			return false;
		}
		if (!vmcs->channel || !vmcs->channel->view.buffer) {
			CSR_SET_TRAP(vmcs->pc, store_amo_access_fault, 0, 0, 1);
		}

		memcpy((uint8_t*)(vmcs->channel->view.buffer + offset), data, size);
		vmcs->channel.ready = 1;

		return true;
	}
}
#endif // HYPRIPC_HPP
