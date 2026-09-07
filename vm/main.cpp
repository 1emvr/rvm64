#include "vmmain.cpp"
int main () {
    return rvm64_start (DEFAULT_MAGIC1, DEFAULT_MAGIC2); // TODO: incoming packets will assign random magics
}

