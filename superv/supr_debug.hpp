#ifndef HYPRDBG_HPP
#define HYPRDBG_HPP
#include <windows.h>

#ifdef DEBUG
#define printf(fmt, ...) printf(fmt, ##__VA_ARGS__);
#else
#define printf(fmt, ...) ((void)0)
#endif


namespace superv::debug {
	void clear_screen() {
		HANDLE h_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
		if (h_stdout == INVALID_HANDLE_VALUE) {
			return;
		}

		CONSOLE_SCREEN_BUFFER_INFO csbi;
		DWORD count;
		DWORD cell_count;
		COORD home_coords = { 0, 0 };

		if (!GetConsoleScreenBufferInfo(h_stdout, &csbi)) {
			return;
		}

		cell_count = csbi.dwSize.X * csbi.dwSize.Y;
		if (!FillConsoleOutputCharacter(h_stdout, ' ', cell_count, home_coords, &count) ||
			!FillConsoleOutputAttribute(h_stdout, csbi.wAttributes, cell_count, home_coords, &count)) {
			return;
		}

		SetConsoleCursorPosition(h_stdout, home_coords);
	}

	void vm_debug_dump(vmcs_t* vmcs, const char *fmt, ...) {
		char inst_buf[256] = { };
		clear_screen();

		va_list args;
		va_start(args, fmt);
		vsnprintf(inst_buf, sizeof(inst_buf), fmt, args);
		va_end(args);

		printf("=== VM DEBUG DUMP ===\n");
		printf("INST: %s", inst_buf);
		printf("PC:  0x%016llx\n", (unsigned long long)vmcs->pc);
		printf("TRAP: %d | HALT: %d | CACHE: %d\n", vmcs->trap, vmcs->halt, vmcs->cache);
		printf("Load Reservation: addr=0x%016llx valid=%llu\n", 
				(unsigned long long)vmcs->load_rsv_addr,
				(unsigned long long)vmcs->load_rsv_valid);

		printf("\n-- Registers (x0-x31) --\n");
		for (int i = 0; i < 32; ++i) {
			printf("x%-2d: 0x%016llx  ", i, (unsigned long long)vmcs->vregs[i]);
			if ((i + 1) % 4 == 0) printf("\n");
		}

		printf("\n-- Scratch Registers (vscratch[0-7]) --\n");
		for (int i = 0; i < 8; ++i) {
			printf("vscratch[%d]: 0x%016llx\n", i, (unsigned long long)vmcs->vscratch[i]);
		}

		printf("\n-- Virtual Stack (Top 10 entries) --\n");
		for (int i = 0; i < 10 && i < VSTACK_MAX_CAPACITY; ++i) {
			printf("vstack[%02d]: 0x%016llx\n", i, (unsigned long long)vmcs->vstack[i]);
		}

		printf("======================\n");
	}
}
#endif // HYPRDBG_HPP
