#include <windows.h>

#include "../include/vmmain.hpp"
#include "../include/vmcommon.hpp"

#include "vmentry.hpp"

namespace rvm64 {
	_native int32_t vm_main(uint64_t magic1, uint64_t magic2) {
		save_host_context();
		rvm64::entry::vm_init(); 

		while (*(volatile uint64_t*)&vmcs->proc.ready != 1ULL) {
			Sleep(10);
		}
		*(volatile uint64_t*)&vmcs->proc.ready = 0ULL;

		rvm64::elf::load_elf_image(vmcs->proc.buffer, vmcs->proc.write_size);
		rvm64::elf::patch_elf_plt_and_set_entry();

		if (setjmp(vmcs->hdw->exit_handler)) {
			goto defer;	
		}

		rvm64::entry::vm_entry(); // patch here before starting the vm -> hook for supervisor
defer:
		// TODO: implant_callback();
		rvm64::entry::vm_exit();
		restore_host_context();

		return vmcs->hdw->csr.m_cause;
	}
};

int main() {
	vmcs_t instance = { };
	vmcs = &instance;

	// TODO: incoming packets/supervisor will assign random magics
    return rvm64::vm_main(VM_MAGIC1, VM_MAGIC2);
}

