#include "vmmain.cpp"
int main () {
	VMCS instance = { };
	Vmcs = &instance;

	// TODO: incoming packets/supervisor will assign random magics
    return VmMain (MAGIC_1, MAGIC_2);
}

