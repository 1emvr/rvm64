#ifndef HYPRSCAN_HPP
#define HYPRSCAN_HPP
#include <windows.h>

namespace superv::scanner {
	uintptr_t find_vm_channel(HANDLE hprocess) {
		SYSTEM_INFO si; 
		uint8_t magic[16];

		GetSystemInfo(&si);
		memcpy(magic+0, &VM_MAGIC1, 8);
		memcpy(magic+8, &VM_MAGIC2, 8);

		for (uint8_t* base = (uint8_t*)si.lpMinimumApplicationAddress;
				base < (uint8_t*)si.lpMaximumApplicationAddress;) {

			MEMORY_BASIC_INFORMATION mbi = { };
			if (!VirtualQueryEx(hprocess, base, &mbi, sizeof(mbi))) {
				break;
			}

			bool scan =
				(mbi.State == MEM_COMMIT) &&
				(mbi.Type  == MEM_PRIVATE) &&
				((mbi.Protect & PAGE_READWRITE) || (mbi.Protect & PAGE_WRITECOPY) ||
				 (mbi.Protect & PAGE_GUARD)); // allow guard pages

			if (scan) {
				SIZE_T to_read = mbi.RegionSize;
				SIZE_T read = 0;
				std::vector<uint8_t> buffer(to_read);

				if (ReadProcessMemory(hprocess, mbi.BaseAddress, buffer.data(), to_read, &read)) {
					for (size_t i = 0; i + sizeof(vm_channel) <= rd; ++i) {
						if (memcmp(buffer.data() + i, magic, 16) == 0) {

							uintptr_t remote = (uintptr_t)mbi.BaseAddress + i;
							vm_channel cand{};
							SIZE_T rd2=0;

							if (ReadProcessMemory(hprocess, (LPCVOID)remote, &cand, sizeof(cand), &rd2) &&
									rd2 == sizeof(cand) &&
									cand.self == remote &&
									cand.view.size == CHANNEL_BUFFER_SIZE &&
									cand.view.bufferfer && cand.vmcs) {
								return remote;
							}
						}
					}
				}
			}
			base += mbi.RegionSize;
		}
		return 0;
	}
}
#endif // HYPRSCAN_HPP
