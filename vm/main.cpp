#include <windows.h>

#include "../include/vmipc.hpp"
#include "../include/vmmain.hpp"
#include "../include/vmcommon.hpp"

#include "vmentry.hpp"

namespace rvm64 {
	_native int32_t vm_main(uint64_t magic1, uint64_t magic2) {
		save_host_context();
		rvm64::ipc::vm_create_channel(magic1, magic2);

		printf("waiting...\n");
		while (true) {
			Sleep(10);
			if (vmcs->channel->ready) {
				break;
			}
		}
		printf("ready.\n");

		if (setjmp(vmcs->exit_handler)) {
			goto defer;	
		}

		rvm64::entry::vm_init(); 
		rvm64::entry::vm_entry(); // patch here before starting the vm -> hook for supervisor
								  
defer:
		// TODO: implant_callback();
		rvm64::entry::vm_exit();
		rvm64::ipc::vm_destroy_channel();

		restore_host_context();
		return vmcs->csr.m_cause;
	}
};

int main() {
	vmcs_t vm_instance = { };
	vmcs = &vm_instance;

	// TODO: incoming packets/supervisor will assign random magics
    return rvm64::vm_main(VM_MAGIC1, VM_MAGIC2);
}

