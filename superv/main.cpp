#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#include "supr_load.hpp"
#include "supr_scan.hpp"

#include "../include/vmmain.hpp"
#include "../include/vmproc.hpp"


VOID PrintUsage () {
	printf ("usage: superv --process <vm> --elf <riscv_elf>\n");
}


INT64 SupervMain (
		_In_ const char* ProcName, 
		_In_ const char* ElfName) 
{
	WIN_PROCESS *Proc = GetProcessInfo (ProcName);
	if (!Proc) {
		printf("[ERR] could not find process information for target\n");
		return 1;
	}

	VMCS *Vmcs = GetVmcs (Proc);
	if (!Vmcs) {
		printf("[ERR] could not load vmcs\n");
		return 1;
	}

	if (! RemoteWriteFile (Proc->Handle, Vmcs, ElfName)) {
		printf("[ERR] could not load elf to the vmcs\n");
		return 1;
	}

	return 0; 
}


int main(int argc, char** argv) {
		const char *ProcName = nullptr;
		const char *ElfName = nullptr;

		if (argc < 5) {
			PrintUsage ();
			return 1;
		}
		for (int i = 0; i < argc; i++) {
			if (strcmp (argv [i], "-p") == 0 || strcmp (argv [i], "--process") == 0) {
				ProcName = argv[i + 1];
			}
			if (strcmp (argv [i], "-e") == 0 || strcmp (argv [i], "--elf") == 0) {
				ElfName = argv [i + 1];
			}
		}
		if (! ProcName || ! ElfName) {
			PrintUsage ();
			return 1;
		}

		return SupervMain (ProcName, ElfName);
}
