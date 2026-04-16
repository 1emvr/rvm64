#include <windows.h>

#include "../include/vmmain.hpp"
#include "../include/vmcommon.hpp"

#include "vmentry.hpp"

namespace rvm64 {
	NATIVE INT32 VmMain (UINT64 magic1, UINT64 magic2) {
		SaveHostContext ();

		VmMemoryInit(); 
		LoadImage (vmcs->Proc.Buffer, vmcs->Proc.WriteSize);

		PatchAndSetEntry ();

		if (setjmp(vmcs->Hdw->ExitHandler)) {
			goto defer;	
		}
defer:
		VmMemoryFree ();
		RestoreHostContext ();

		return vmcs->Hdw->Csr.MCause;
	}
};

int main () {
	VMCS instance = { };
	vmcs = &instance;

	// TODO: incoming packets/supervisor will assign random magics
    return VmMain (VM_MAGIC1, VM_MAGIC2);
}

