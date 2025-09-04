#ifndef HYPRIPC_HPP
#define HYPRIPC_HPP

#include "vmmain.hpp"
#include "vmmem.hpp"

namespace rvm64::ipc {
	void vm_destroy_channel() {
		if (vmcs->channel.view.buffer) {
			VirtualFree((LPVOID)vmcs->channel.view.buffer, 0, MEM_FREE);
			vmcs->channel.view.buffer = 0;
			vmcs->channel.view.size = 0;
		}
	}

	void vm_create_channel(uint64_t magic1, uint64_t magic2) {
		HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
		HMODULE hmodule = GetModuleHandle(0);

		// vm ipc channel starts by copying it's own pointers for the supervisor to use
		vmcs->channel.self = (uint64_t)&vmcs->channel;
		vmcs->channel.magic1 = magic1;
		vmcs->channel.magic2 = magic2;

		vmcs->channel.view.size = CHANNEL_BUFFER_SIZE;
		vmcs->channel.view.buffer = (uint64_t)VirtualAlloc(nullptr, CHANNEL_BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); 

		if (!vmcs->channel.view.buffer) {
			CSR_SET_TRAP(vmcs->pc, GetLastError(), 0, 0, 1);
		}
	}

	bool read_channel_buffer(uintptr_t data, uintptr_t offset, size_t size) {
		if (!data || offset > CHANNEL_BUFFER_SIZE || size > CHANNEL_BUFFER_SIZE - offset) {
			return false;
		}
		if (!vmcs->channel.view.buffer) {
			CSR_SET_TRAP(vmcs->pc, load_access_fault, 0, 0, 1);
		}
		if (!vmcs->channel.ready) {
			return false;
		}

		memcpy((uint8_t*)data, (uint8_t*)(vmcs->channel.view.buffer + offset), size);
		vmcs->channel.ready = 0;

		return true;
	}

	bool write_channel_buffer(const uintptr_t data, uintptr_t offset, size_t size) {
		if (!data || offset > CHANNEL_BUFFER_SIZE || size > CHANNEL_BUFFER_SIZE - offset) {
			return false;
		}
		if (!vmcs->channel.view.buffer) {
			CSR_SET_TRAP(vmcs->pc, store_amo_access_fault, 0, 0, 1);
		}

		memcpy((uint8_t*)(vmcs->channel.view.buffer + offset), (uint8_t*)data, size);

		vmcs->channel.view.write_size = (uint64_t)size;
		vmcs->channel.ready = 1;

		return true;
	}
}
#endif // HYPRIPC_HPP
