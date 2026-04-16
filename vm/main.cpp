#include "vmmain.cpp"
int main () {
    return VmStart (INTERNAL_MAGIC1, INTERNAL_MAGIC2); // TODO: incoming packets will assign random magics
}

