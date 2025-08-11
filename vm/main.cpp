#include <windows.h>

#include "vmmain.hpp"
#include "vmentry.hpp"
#include "vmcommon.hpp"

namespace rvm64 {
	_native int32_t vm_main(channel *packet) {
		save_host_context();

		if (setjmp(vmcs->exit_handler)) {
			goto defer;	
		}

		rvm64::entry::vm_init(packet->address, packet->size); 
		rvm64::entry::vm_entry(); // patch here before starting the vm -> hook for supervisor

defer:
		rvm64::entry::vm_exit();

		restore_host_context();
		return vmcs->csr.m_cause;
	}
};

int main() {
	vmcs_t vm_instance = { };
	vmcs = &vm_instance;


	while (true) {
		if (rvm64::mock::read_packet()) {
			break;
		}
		Sleep(10);
	}

    rvm64::vm_main(packet);
	// TODO: destroy memory view
}

