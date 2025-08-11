#ifndef VMDBG_HPP
#define VMDBG_HPP
#include <windows.h>

#ifdef DEBUG
#define dbgprint(fmt, ...) printf(fmt, ##__VA_ARGS__);
#else
#define dbgprint(fmt, ...) ((void)0)
#endif


void clear_screen() {
	HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hStdOut == INVALID_HANDLE_VALUE) return;

	CONSOLE_SCREEN_BUFFER_INFO csbi;
	DWORD count;
	DWORD cellCount;
	COORD homeCoords = { 0, 0 };

	if (!GetConsoleScreenBufferInfo(hStdOut, &csbi)) return;
	cellCount = csbi.dwSize.X * csbi.dwSize.Y;

	if (!FillConsoleOutputCharacter(hStdOut, ' ', cellCount, homeCoords, &count)) return;
	if (!FillConsoleOutputAttribute(hStdOut, csbi.wAttributes, cellCount, homeCoords, &count)) return;

	SetConsoleCursorPosition(hStdOut, homeCoords);
}

void vm_debug_dump(const char *fmt, ...) {
#ifndef DEBUG
	return; // dogshit
#endif
	char inst_buf[256] = { };
	clear_screen();

	va_list args;
	va_start(args, fmt);
	vsnprintf(inst_buf, sizeof(inst_buf), fmt, args);
	va_end(args);

	dbgprint("=== VM DEBUG DUMP ===\n");
	dbgprint("INST: %s", inst_buf);
	dbgprint("PC:  0x%016llx\n", (unsigned long long)vmcs->pc);
	dbgprint("TRAP: %d | HALT: %d | CACHE: %d\n", vmcs->trap, vmcs->halt, vmcs->cache);
	dbgprint("Load Reservation: addr=0x%016llx valid=%llu\n", 
	         (unsigned long long)vmcs->load_rsv_addr,
	         (unsigned long long)vmcs->load_rsv_valid);

	dbgprint("\n-- Registers (x0-x31) --\n");
	for (int i = 0; i < 32; ++i) {
		dbgprint("x%-2d: 0x%016llx  ", i, (unsigned long long)vmcs->vregs[i]);
		if ((i + 1) % 4 == 0) dbgprint("\n");
	}

	dbgprint("\n-- Scratch Registers (vscratch[0-7]) --\n");
	for (int i = 0; i < 8; ++i) {
		dbgprint("vscratch[%d]: 0x%016llx\n", i, (unsigned long long)vmcs->vscratch[i]);
	}

	dbgprint("\n-- Virtual Stack (Top 10 entries) --\n");
	for (int i = 0; i < 10 && i < VSTACK_MAX_CAPACITY; ++i) {
		dbgprint("vstack[%02d]: 0x%016llx\n", i, (unsigned long long)vmcs->vstack[i]);
	}

	dbgprint("======================\n");
}
#endif // VMDBG_HPP
