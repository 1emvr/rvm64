#ifndef HYPRDBG_HPP
#define HYPRDBG_HPP
#include <windows.h>
#include "../include/"


namespace superv::debug {
	void clear_screen() {
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		DWORD count = 0, cell_count = 0;
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

	void send_signal(win_process* proc, vm_channel* channel, uint64_t signal) {
		switch(signal) {
			case SIGNAL_NEXT: 
				{
					uint64_t ready = 1;
					if (!set_channel_ready(proc->handle, channel, ready)) {
						printf("[ERR] FATAL! could not send the enter key-state to channel->ready\n");
						return;
					}
				}
			default:
				break;
		}
	}

	void read_client_vmcs() {

	}

	void decode_client_vmcs() {

	}

	void print_decoded() {

	}

	void user_loop() {
		// get cmd
		// get key press
		// check key press + cmd
		// send whatever
		// read client
		// decode client
		// print decoded
	}
}
#endif // HYPRDBG_HPP
