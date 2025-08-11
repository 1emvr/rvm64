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
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		DWORD count;
		DWORD cell_count;
		COORD home_coords = { 0, 0 };

		HANDLE h_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
		if (h_stdout == INVALID_HANDLE_VALUE) {
			return;
		}
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

	void vm_debug_dump(vm_channel *chan) {
		char inst_buf[256] = { };
		clear_screen();

		va_list args;
		va_start(args, fmt);
		vsnprintf(inst_buf, sizeof(inst_buf), fmt, args);
		va_end(args);

	}
}
#endif // HYPRDBG_HPP
