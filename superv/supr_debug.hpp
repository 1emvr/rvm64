#ifndef HYPRDBG_HPP
#define HYPRDBG_HPP
#include <windows.h>
#include <inttypes.h>
#include <string>
#include <iostream>
#include <cstdint>
#include <cstddef>

#include "../include/vmipc.hpp"
#include "../include/vmmain.hpp"
#include "../include/vmcommon.hpp"

#define CMD_NEXT 0x1ULL

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
		if (!FillConsoleOutputCharacterA(h_stdout, ' ', cell_count, home_coords, &count) ||
			!FillConsoleOutputAttribute(h_stdout, csbi.wAttributes, cell_count, home_coords, &count)) {
			return;
		}

		SetConsoleCursorPosition(h_stdout, home_coords);
	}

	void send_signal(win_process* proc, vm_channel* channel, uint64_t signal) {
		switch(signal) {
			case CMD_NEXT: 
				{
					rvm64::ipc::set_channel_ready(proc->handle, channel, 1);
					break;
				}
			default:
				break;
		}
	}

	void print_decode(win_process* proc, vm_channel* channel) {
		vmcs_t vmcs{ };

		if (!rvm64::memory::read_process_memory(proc->handle, (uintptr_t)channel->self, (uint8_t*)&vmcs, sizeof(vmcs))) {
			std::printf("[ERR] decoder unable to read process memory (vmcs): GetLastError=0x%lx\n", (unsigned long)GetLastError());
			return;
		}

		clear_screen();

		std::printf("[DBG] vmcs.pc = 0x%016" PRIxPTR "\n", (uintptr_t)vmcs.pc);
		std::printf("[DBG] vmcs->vregs:\n");

		for (int i = 0; i < 32; ++i) {
			std::printf("x%02d = 0x%016" PRIxPTR "%s", i, (uintptr_t)vmcs.vregs[i], ((i + 1) % 8 == 0) ? "\n" : "  ");
		}

		std::printf("\n");
		
		// TODO: read csr registers
		// TODO: read data from vmcs.pc
		// TODO: read stack from vmcs.vregs[sp]
	}

	void user_loop(win_process* proc, vm_channel* channel) {
		std::string last_cmd;
		std::cout << "[INF] press enter to continue.\n" << std::flush;

		if (!std::getline(std::cin, last_cmd)) {
			return;
		}
		if (last_cmd == "q" || last_cmd == "quit" || last_cmd == "exit") {
			return;
		}

		last_cmd.clear();

		while (true) {
			print_decode(proc, channel);

			std::cout << "> " << std::flush;
			std::string cmd;

			if (!std::getline(std::cin, cmd)) break;
			if (cmd.empty()) cmd = last_cmd; else last_cmd = cmd;

			if (cmd == "q" || cmd == "quit" || cmd == "exit") {
				break;
			}

			if (cmd == "clr" || cmd == "clear") {
				clear_screen();
				continue;
			}

			if (cmd == "n" || cmd == "next") {
				send_signal(proc, channel, CMD_NEXT);
				continue;
			}

			// TODO: other commands...

			Sleep(50);
		}

		clear_screen();
	}
}
#endif // HYPRDBG_HPP
