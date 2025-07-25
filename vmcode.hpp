#ifndef VMCODE_H
#define VMCODE_H
#include "vmmain.hpp"
#include "vmcrypt.hpp"
#include "vmmem.hpp"
#include "vmrwx.hpp"
#include "vmutils.hpp"

namespace rvm64::decoder {
	enum handler_index : uint8_t {
		// ITYPE
		_rv_addi, _rv_slti, _rv_sltiu, _rv_xori,
		_rv_ori, _rv_andi, _rv_slli, _rv_srli,
		_rv_srai, _rv_addiw, _rv_slliw, _rv_srliw,
		_rv_sraiw, _rv_lb, _rv_lh, _rv_lw,
		_rv_lbu, _rv_lhu, _rv_lwu, _rv_ld,
		_rv_flq, _rv_fence, _rv_fence_i, _rv_jalr,
		_rv_ecall, _rv_ebreak, _rv_csrrw, _rv_csrrs,
		_rv_csrrc, _rv_csrrwi, _rv_csrrsi, _rv_csrrci,
		_rv_fclass_d, _rv_lrw, _rv_lrd, _rv_fmv_d_x,
		_rv_fcvt_s_d, _rv_fcvt_d_s, _rv_fcvt_w_d, _rv_fcvt_wu_d,
		_rv_fcvt_d_w, _rv_fcvt_d_wu,

		// RTYPE
		_rv_fadd_d, _rv_fsub_d, _rv_fmul_d, _rv_fdiv_d,
		_rv_fsgnj_d, _rv_fsgnjn_d, _rv_fsgnjx_d,
		_rv_fmin_d, _rv_fmax_d, _rv_feq_d, _rv_flt_d,
		_rv_fle_d, _rv_scw, _rv_amoswap_w, _rv_amoadd_w,
		_rv_amoxor_w, _rv_amoand_w, _rv_amoor_w, _rv_amomin_w,
		_rv_amomax_w, _rv_amominu_w, _rv_amomaxu_w,
		_rv_scd, _rv_amoswap_d, _rv_amoadd_d,
		_rv_amoxor_d, _rv_amoand_d, _rv_amoor_d, _rv_amomin_d,
		_rv_amomax_d, _rv_amominu_d, _rv_amomaxu_d,
		_rv_addw, _rv_subw, _rv_mulw, _rv_srlw,
		_rv_sraw, _rv_divuw, _rv_sllw, _rv_divw,
		_rv_remw, _rv_remuw, _rv_add, _rv_sub,
		_rv_mul, _rv_sll, _rv_mulh, _rv_slt,
		_rv_mulhsu, _rv_sltu, _rv_mulhu, _rv_xor,
		_rv_div, _rv_srl, _rv_sra, _rv_divu,
		_rv_or, _rv_rem, _rv_and, _rv_remu,

		// STYPE
		_rv_sb, _rv_sh, _rv_sw, _rv_sd,
		_rv_fsw, _rv_fsd,

		// BTYPE
		_rv_beq, _rv_bne, _rv_blt, _rv_bge,
		_rv_bltu, _rv_bgeu,

		// UTYPE/JTYPE
		_rv_lui, _rv_auipc, _rv_jal
	};

	struct opcode {
		uint8_t mask;
		typenum type;
	};

	_data opcode encoding[] = {
		{0b1010011, rtype}, {0b1000011, rtype}, {0b0110011, rtype}, {0b1000111, r4type}, {0b1001011, r4type}, {0b1001111, r4type},
		{0b0000011, itype}, {0b0001111, itype}, {0b1100111, itype}, {0b0010011, itype}, {0b1110011, itype}, {0b0011011, itype},
		{0b0100011, stype}, {0b0100111, stype}, {0b1100011, btype}, {0b0010111, utype}, {0b0110111, utype}, {0b1101111, jtype},
	};

	_vmcall void vm_decode(uint32_t opcode) {
		uint8_t decoded = 0;
		uint8_t opcode7 = opcode & 0x7F;

		for (int idx = 0; idx < sizeof(encoding); idx++) {
			if (encoding[idx].mask == opcode7) {
				decoded = encoding[idx].type;
				break;
			}
		}
		if (!decoded) {
			CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, opcode, 1);
		}

		switch(decoded) {
			case itype: 
			{
				uint8_t func3 = (opcode >> 12) & 0x7;
				scr_write(uint8_t, screnum::rd, (opcode >> 7) & 0x1F);
				scr_write(uint8_t, screnum::rs1, (opcode >> 15) & 0x1F);

				switch(opcode7) {
					case 0b1110011:
					{
						auto imm = imm_i(opcode);
						switch (imm) {
							case 0b000000000000: { unwrap_opcall(_rv_ecall); break; }
							case 0b000000000001: { unwrap_opcall(_rv_ebreak); break; }
							default: break;
						}
						break;
					}
					case 0b0010011: 
					{
						switch(func3) {
							case 0b000: { scr_write(int32_t, imm, imm_i(opcode)); unwrap_opcall(_rv_addi); break; }
							case 0b010: { scr_write(int32_t, imm, imm_i(opcode)); unwrap_opcall(_rv_slti); break; }
							case 0b011: { scr_write(int32_t, imm, imm_i(opcode)); unwrap_opcall(_rv_sltiu); break; }
							case 0b100: { scr_write(int32_t, imm, imm_i(opcode)); unwrap_opcall(_rv_xori); break; }
							case 0b110: { scr_write(int32_t, imm, imm_i(opcode)); unwrap_opcall(_rv_ori);  break; }
							case 0b111: { scr_write(int32_t, imm, imm_i(opcode)); unwrap_opcall(_rv_andi); break; }
							case 0b001: { scr_write(int32_t, imm, shamt_i(opcode)); unwrap_opcall(_rv_slli); break; }
							case 0b101: {
								uint8_t func7 = (opcode >> 25) & 0x7F; // NOTE: "opcode >> 24" (?) Not sure 
								switch(func7) {
									case 0b0000000: { scr_write(int32_t, imm, shamt_i(opcode)); unwrap_opcall(_rv_srli); break; }
									case 0b0100000: { scr_write(int32_t, imm, shamt_i(opcode)); unwrap_opcall(_rv_srai); break; }
									default: break;
								}
							}
							default: break;
						}
						break;
					}
					case 0b0011011: 
					{
						switch(func3) {
							case 0b000: { scr_write(int32_t, imm, imm_i(opcode)); unwrap_opcall(_rv_addiw); break; }
							case 0b001: { scr_write(int32_t, imm, shamt_i(opcode)); unwrap_opcall(_rv_slliw); break; }
							case 0b101: 
							{
								uint8_t func7 = (opcode >> 25) & 0x7F;
								switch(func7) {
									case 0b0000000: { scr_write(int32_t, imm, shamt_i(opcode)); unwrap_opcall(_rv_srliw); break; }
									case 0b0100000: { scr_write(int32_t, imm, shamt_i(opcode)); unwrap_opcall(_rv_sraiw); break; }
									default: break;
								}
							}
							default: break;
						}
						break;
					}
					case 0b0000011: 
					{
						switch(func3) {
							case 0b000: { scr_write(int32_t, imm, imm_i(opcode)); unwrap_opcall(_rv_lb); break;  }
							case 0b001: { scr_write(int32_t, imm, imm_i(opcode)); unwrap_opcall(_rv_lh); break;  }
							case 0b010: { scr_write(int32_t, imm, imm_i(opcode)); unwrap_opcall(_rv_lw); break;  }
							case 0b100: { scr_write(int32_t, imm, imm_i(opcode)); unwrap_opcall(_rv_lbu); break; }
							case 0b101: { scr_write(int32_t, imm, imm_i(opcode)); unwrap_opcall(_rv_lhu); break; }
							case 0b110: { scr_write(int32_t, imm, imm_i(opcode)); unwrap_opcall(_rv_lwu); break; }
							case 0b011: { scr_write(int32_t, imm, imm_i(opcode)); unwrap_opcall(_rv_ld); break;  }
							default: break;
						}
						break;
					}
					case 0b1100111:
					{
						switch(func3) {
							case 0b000: { scr_write(int32_t, imm, imm_i(opcode)); unwrap_opcall(_rv_jalr); break; }
						}
					}
					default: break;
				}
				break;
			}

			case rtype: 
			{
				scr_write(uint8_t, screnum::rd, (opcode >> 7) & 0x1F);
				scr_write(uint8_t, screnum::rs1, (opcode >> 15) & 0x1F);
				scr_write(uint8_t, screnum::rs2, (opcode >> 20) & 0x1F);

				switch(opcode7) {
					case 0b1010011: 
					{
						uint8_t func7 = (opcode >> 25) & 0x7F;
						switch(func7) {
							case 0b0000001: { unwrap_opcall(_rv_fadd_d); break; }
							case 0b0000101: { unwrap_opcall(_rv_fsub_d); break; }
							case 0b0001001: { unwrap_opcall(_rv_fmul_d); break; }
							case 0b0001101: { unwrap_opcall(_rv_fdiv_d); break; }
							case 0b1111001: { unwrap_opcall(_rv_fmv_d_x); break; }
							case 0b0100000: 
							{
								uint8_t fcvt_mask = (opcode >> 20) & 0x1F;
								switch(fcvt_mask) {
									case 0b00001: { unwrap_opcall(_rv_fcvt_s_d); break; }
									default: break;
								}
								break;
							}
							case 0b0100001: 
							{
								uint8_t fcvt_mask = (opcode >> 20) & 0x1F;
								switch(fcvt_mask) {
									case 0b00000: { unwrap_opcall(_rv_fcvt_d_s); break; }
									default: break;
								}
								break;
							}
							case 0b1100001: 
							{
								uint8_t fcvt_mask = (opcode >> 20) & 0x1F;
								switch(fcvt_mask) {
									case 0b00000: { unwrap_opcall(_rv_fcvt_w_d); break; }
									case 0b00001: { unwrap_opcall(_rv_fcvt_wu_d); break; }
									default: break;
								}
								break;
							}
							case 0b1101001: 
							{
								uint8_t fcvt_mask = (opcode >> 20) & 0x1F;
								switch(fcvt_mask) {
									case 0b00000: { unwrap_opcall(_rv_fcvt_d_w); break; }
									case 0b00001: { unwrap_opcall(_rv_fcvt_d_wu); break; }
									default: break;
								}
								break;
							}
							case 0b0010001: 
							{
								uint8_t func3 = (opcode >> 12) & 0x7;
								switch(func3) {
									case 0b000: { unwrap_opcall(_rv_fsgnj_d); break; }
									case 0b001: { unwrap_opcall(_rv_fsgnjn_d); break; }
									case 0b010: { unwrap_opcall(_rv_fsgnjx_d); break; }
									default: break;
								}
								break;
							}
							case 0b0010101: 
							{
								uint8_t func3 = (opcode >> 12) & 0x7;
								switch(func3) {
									case 0b000: { unwrap_opcall(_rv_fmin_d); break; }
									case 0b001: { unwrap_opcall(_rv_fmax_d); break; }
									default: break;
								}
								break;
							}
							case 0b1010001: 
							{
								uint8_t func3 = (opcode >> 12) & 0x7;
								switch(func3) {
									case 0b010: { unwrap_opcall(_rv_feq_d); break; }
									case 0b001: { unwrap_opcall(_rv_flt_d); break; }
									case 0b000: { unwrap_opcall(_rv_fle_d); break; }
									default: break;
								}
								break;
							}
							case 0b1110001: 
							{
								uint8_t func3 = (opcode >> 12) & 0x7;
								switch(func3) {
									case 0b001: { unwrap_opcall(_rv_fclass_d); break; }
									default: break;
								}
								break;
							}
							default: break;
						}
						break;
					}
					case 0b0101111: 
					{
						// TODO: func5 might be incorrect.
						uint8_t func7 = (opcode >> 25) & 0x7F;
						uint8_t func5 = (func7 >> 2) & 0x1F;
						uint8_t func3 = (opcode >> 12) & 0x7;

						switch(func3) {
							case 0b010: 
							{
								switch(func5) {
									case 0b00010: { unwrap_opcall(_rv_lrw); break; }
									case 0b00011: { unwrap_opcall(_rv_scw); break; }
									case 0b00001: { unwrap_opcall(_rv_amoswap_w); break; }
									case 0b00000: { unwrap_opcall(_rv_amoadd_w); break; }
									case 0b00100: { unwrap_opcall(_rv_amoxor_w); break; }
									case 0b01100: { unwrap_opcall(_rv_amoand_w); break; }
									case 0b01000: { unwrap_opcall(_rv_amoor_w); break; }
									case 0b10000: { unwrap_opcall(_rv_amomin_w); break; }
									case 0b10100: { unwrap_opcall(_rv_amomax_w); break; }
									case 0b11000: { unwrap_opcall(_rv_amominu_w); break; }
									case 0b11100: { unwrap_opcall(_rv_amomaxu_w); break; }
									default: break;
								}
								break;
							}
							case 0b011: 
							{
								switch(func5) {
									case 0b00010: { unwrap_opcall(_rv_lrd); break; }
									case 0b00011: { unwrap_opcall(_rv_scd); break; }
									case 0b00001: { unwrap_opcall(_rv_amoswap_d); break; }
									case 0b00000: { unwrap_opcall(_rv_amoadd_d); break; }
									case 0b00100: { unwrap_opcall(_rv_amoxor_d); break; }
									case 0b01100: { unwrap_opcall(_rv_amoand_d); break; }
									case 0b01000: { unwrap_opcall(_rv_amoor_d); break; }
									case 0b10000: { unwrap_opcall(_rv_amomin_d); break; }
									case 0b10100: { unwrap_opcall(_rv_amomax_d); break; }
									case 0b11000: { unwrap_opcall(_rv_amominu_d); break; }
									case 0b11100: { unwrap_opcall(_rv_amomaxu_d); break; }
									default: break;
								}
								break;
							}
							default: break;
						}
						break;
					}
					case 0b0111011: 
					{
						uint8_t func7 = (opcode >> 25) & 0x7F;
						uint8_t func3 = (opcode >> 12) & 0x7;

						switch(func3) {
							case 0b000: 
							{
								switch(func7) {
									case 0b0000000: { unwrap_opcall(_rv_addw); break; }
									case 0b0100000: { unwrap_opcall(_rv_subw); break; }
									case 0b0000001: { unwrap_opcall(_rv_mulw); break; }
									default: break;
								}
								break;
							}
							case 0b101: 
							{
								switch(func7) {
									case 0b0000000: { unwrap_opcall(_rv_srlw); break; }
									case 0b0100000: { unwrap_opcall(_rv_sraw); break; }
									case 0b0000001: { unwrap_opcall(_rv_divuw); break; }
									default: break;
								}
								break;
							}
							case 0b001: { unwrap_opcall(_rv_sllw); break; }
							case 0b100: { unwrap_opcall(_rv_divw); break; }
							case 0b110: { unwrap_opcall(_rv_remw); break; }
							case 0b111: { unwrap_opcall(_rv_remuw); break; }
							default: break;
						}
						break;
					}
					case 0b0110011: 
					{
						uint8_t func7 = (opcode >> 25) & 0x7F;
						uint8_t func3 = (opcode >> 12) & 0x7;

						switch(func3) {
							case 0b000: 
							{
								switch(func7) {
									case 0b0000000: { unwrap_opcall(_rv_add); break; }
									case 0b0100000: { unwrap_opcall(_rv_sub); break; }
									case 0b0000001: { unwrap_opcall(_rv_mul); break; }
									default: break;
								}
								break;
							}
							case 0b001: 
							{
								switch(func7) {
									case 0b0000000: { unwrap_opcall(_rv_sll); break; }
									case 0b0000001: { unwrap_opcall(_rv_mulh); break; }
									default: break;
								}
								break;
							}
							case 0b010: 
							{
								switch(func7) {
									case 0b0000000: { unwrap_opcall(_rv_slt); break; }
									case 0b0000001: { unwrap_opcall(_rv_mulhsu); break; }
									default: break;
								}
								break;
							}
							case 0b011: 
							{
								switch(func7) {
									case 0b0000000: { unwrap_opcall(_rv_sltu); break; }
									case 0b0000001: { unwrap_opcall(_rv_mulhu); break; }
									default: break;
								}
								break;
							}
							case 0b100: 
							{
								switch(func7) {
									case 0b0000000: { unwrap_opcall(_rv_xor); break; }
									case 0b0000001: { unwrap_opcall(_rv_div); break; }
									default: break;
								}
								break;
							}
							case 0b101: 
							{
								switch(func7) {
									case 0b0000000: { unwrap_opcall(_rv_srl); break; }
									case 0b0100000: { unwrap_opcall(_rv_sra); break; }
									case 0b0000001: { unwrap_opcall(_rv_divu); break; }
									default: break;
								}
								break;
							}
							case 0b110: 
							{
								switch(func7) {
									case 0b0000000: { unwrap_opcall(_rv_or); break; }
									case 0b0000001: { unwrap_opcall(_rv_rem); break; }
									default: break;
								}
								break;
							}
							case 0b111: 
							{
								switch(func7) {
									case 0b0000000: { unwrap_opcall(_rv_and); break; }
									case 0b0000001: { unwrap_opcall(_rv_remu); break; }
									default: break;
								}
								break;
							}
							default: break;
						}
						break;
					}
					default: break;
				}
				break;
			}

			case stype: 
			{
				uint8_t func3 = (opcode >> 12) & 0x7;

				scr_write(uint8_t, screnum::rs2, (opcode >> 20) & 0x1F);
				scr_write(uint8_t, screnum::rs1, (opcode >> 15) & 0x1F);
				scr_write(int32_t, imm, imm_s(opcode));

				switch(opcode7) {
					case 0b0100011: 
					{
						switch(func3) {
							case 0b000: { unwrap_opcall(_rv_sb); break; }
							case 0b001: { unwrap_opcall(_rv_sh); break; }
							case 0b010: { unwrap_opcall(_rv_sw); break; }
							case 0b011: { unwrap_opcall(_rv_sd); break; }
							default: break;
						}
						break;
					}
					case 0b0100111: {
						switch(func3) {
							case 0b010: { unwrap_opcall(_rv_fsw); break; }
							case 0b011: { unwrap_opcall(_rv_fsd); break; }
							default: break;
						}
						break;
					}
					default: break;
				}
				break;
			}

			case btype: 
			{
				uint8_t func3 = (opcode >> 12) & 0x7;

				scr_write(uint8_t, screnum::rs2, (opcode >> 20) & 0x1F);
				scr_write(uint8_t, screnum::rs1, (opcode >> 15) & 0x1F);
				scr_write(int32_t, imm, imm_b(opcode));

				switch(func3) {
					case 0b000: { unwrap_opcall(_rv_beq); break; }
					case 0b001: { unwrap_opcall(_rv_bne); break; }
					case 0b100: { unwrap_opcall(_rv_blt); break; }
					case 0b101: { unwrap_opcall(_rv_bge); break; }
					case 0b110: { unwrap_opcall(_rv_bltu); break; }
					case 0b111: { unwrap_opcall(_rv_bgeu); break; }
					default: break;
				}
				break;
			}

			case utype: 
			{
				scr_write(uint8_t, screnum::rd, (opcode >> 7) & 0x1F);
				scr_write(int32_t, screnum::imm, imm_u(opcode));

				switch(opcode7) {
					case 0b0110111: { unwrap_opcall(_rv_lui); break; }
					case 0b0010111: { unwrap_opcall(_rv_auipc); break; }
					default: break;
				}
				break;
			}

			case jtype:
			{
				scr_write(uint8_t, screnum::rd, (opcode >> 7) & 0x1F);
				scr_write(int32_t, screnum::imm, imm_j(opcode));

				switch(opcode7) {
					case 0b1101111: { unwrap_opcall(_rv_jal); break; }
					default: break;
				}
				break;
			}

			default: {
				CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, opcode, 1);
				break;
			}
		}
	}
};

namespace rvm64::operations {
	union {
		double d;
		uint64_t u;
	} converter;

	_vmcall bool is_nan(double x) {
		converter.d = x;

		uint64_t exponent = (converter.u & EXPONENT_MASK) >> 52;
		uint64_t fraction = converter.u & FRACTION_MASK;

		return (exponent == 0x7FF) && (fraction != 0);
	}

	namespace itype {
		_vmcall void rv_lrw() {
			uint8_t _rd = 0, _rs1 = 0; uintptr_t address = 0; int32_t value = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);

			reg_read(uintptr_t, address, _rs1);
			WaitForSingleObject(vmcs_mutex, INFINITE);

			mem_read(int32_t, value, address);
			reg_write(int32_t, _rd, value);

			ReleaseMutex(vmcs_mutex);
		}

		_vmcall void rv_lrd() {
			uint8_t _rd = 0, _rs1 = 0; uintptr_t address = 0; int64_t value = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);

			reg_read(uintptr_t, address, _rs1);
			WaitForSingleObject(vmcs_mutex, INFINITE);

			mem_read(int64_t, value, address);
			reg_write(int64_t, _rd, value);

			ReleaseMutex(vmcs_mutex);
		}

		_vmcall void rv_fmv_d_x() {
			uint8_t _rd = 0, _rs1 = 0; int64_t v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);

			reg_read(int64_t, v1, _rs1);
			reg_write(int64_t, _rd, v1);
		}

		_vmcall void rv_fcvt_s_d() {
			uint8_t _rd = 0, _rs1 = 0; float v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);

			reg_read(double, v1, _rs1);
			reg_write(float, _rd, v1);
		}

		_vmcall void rv_fcvt_d_s() {
			uint8_t _rd = 0, _rs1 = 0; double v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);

			reg_read(float, v1, _rs1);
			reg_write(double, _rd, v1);
		}

		_vmcall void rv_fcvt_w_d() {
			uint8_t _rd = 0, _rs1 = 0; int32_t v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);

			reg_read(double, v1, _rs1);
			reg_write(int32_t, _rd, v1);
		}

		_vmcall void rv_fcvt_wu_d() {
			uint8_t _rd = 0, _rs1 = 0; uint32_t v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);

			reg_read(double, v1, _rs1);
			reg_write(uint32_t, _rd, v1);
		}

		_vmcall void rv_fcvt_d_w() {
			uint8_t _rd = 0, _rs1 = 0; int32_t v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);

			reg_read(int32_t, v1, _rs1);
			reg_write(double, _rd, v1);
		}

		_vmcall void rv_fcvt_d_wu() {
			uint8_t _rd = 0, _rs1 = 0; uint32_t v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);

			reg_read(uint32_t, v1, _rs1);
			reg_write(double, _rd, v1);
		}

		// NOTE: maybe not even real...
		_vmcall void rv_fclass_d() {
			uint8_t _rd = 0, _rs1 = 0; double v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);

			reg_read(double, v1, _rs1);
			converter.d = v1;

			const uint64_t exponent = (converter.u >> 52) & 0x7FF;
			const uint64_t fraction = converter.u & 0xFFFFFFFFFFFFF;
			const uint64_t sign = converter.u >> 63;

			if (exponent == 0x7FF) {
				if (fraction == 0) {
					if (sign == 0) {
						reg_write(int, _rd, 0x7); // +inf
					} else {
						reg_write(int, _rd, 0x0); // -inf
					}
				} else {
					if (fraction & (1LL << 51)) {
						reg_write(int, _rd, 0x8); // quiet NaN
					} else {
						reg_write(int, _rd, 0x9); // signaling NaN
					}
				}
			} else if (exponent == 0) {
				if (fraction == 0) {
					if (sign == 0) {
						reg_write(int, _rd, 0x4); // +0
					} else {
						reg_write(int, _rd, 0x3); // -0
					}
				} else {
					if (sign == 0) {
						reg_write(int, _rd, 0x5); // +subnormal
					} else {
						reg_write(int, _rd, 0x2); // -subnormal
					}
				}
			} else {
				if (sign == 0) {
					reg_write(int, _rd, 0x6); // +normal
				} else {
					reg_write(int, _rd, 0x1); // -normal
				}
			}
		}

		// NOTE: immediates are always signed unless there's a bitwise operation
		_vmcall void rv_addi() {
			uint8_t _rd = 0, _rs1 = 0; int32_t _imm = 0; int64_t v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(int32_t, _imm, imm);

			reg_read(int64_t, v1, _rs1);
			reg_write(int64_t, _rd, (v1 + _imm));
		}

		_vmcall void rv_slti() {
			uint8_t _rd = 0, _rs1 = 0; int32_t _imm = 0; int64_t v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(int32_t, _imm, imm);

			reg_read(int64_t, v1, _rs1);
			reg_write(int64_t, _rd, ((v1 < _imm) ? 1 : 0));
		}

		_vmcall void rv_sltiu() {
			uint8_t _rd = 0, _rs1 = 0; int32_t _imm = 0; uint64_t v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(int32_t, _imm, imm);

			reg_read(uint64_t, v1, _rs1);
			reg_write(uint64_t, _rd, ((v1 < (uint32_t)_imm) ? 1 : 0));
		}

		_vmcall void rv_xori() {
			uint8_t _rd = 0, _rs1 = 0; int32_t _imm = 0; int64_t v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(int32_t, _imm, imm);

			reg_read(int64_t, v1, _rs1);
			reg_write(int64_t, _rd, (v1 ^ _imm));
		}

		_vmcall void rv_ori() {
			uint8_t _rd = 0, _rs1 = 0; int32_t _imm = 0; int64_t v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(int32_t, _imm, imm);

			reg_read(int64_t, v1, _rs1);
			reg_write(int64_t, _rd, (v1 | _imm));
		}

		_vmcall void rv_andi() {
			uint8_t _rd = 0, _rs1 = 0; int32_t _imm = 0; int64_t v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(int32_t, _rs1, rs1);
			scr_read(int32_t, _imm, imm);

			reg_read(int64_t, v1, _rs1);
			reg_write(int64_t, _rd, (v1 & _imm));
		}

		_vmcall void rv_slli() {
			uint8_t _rd = 0, _rs1 = 0; uint32_t _shamt = 0; int64_t v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint32_t, _shamt, imm);

			reg_read(uint64_t, v1, _rs1);
			reg_write(uint64_t, _rd, (v1 << (_shamt & 0x1F)));
		}

		_vmcall void rv_srli() {
			uint8_t _rd = 0, _rs1 = 0; uint32_t _shamt = 0; uint64_t v1 = 0; 

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint32_t, _shamt, imm);

			reg_read(uint64_t, v1, _rs1);
			reg_write(uint64_t, _rd, v1 >> (_shamt & 0x1F));
		}

		_vmcall void rv_srai() {
			uint8_t _rd = 0, _rs1 = 0; uint32_t _shamt = 0; uint64_t v1 = 0; 

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint32_t, _shamt, imm);

			reg_read(uint64_t, v1, _rs1);
			reg_write(uint64_t, _rd, v1 >> (_shamt & 0x1F));
		}

		_vmcall void rv_addiw() {
			uint8_t _rd = 0, _rs1 = 0; int32_t v1 = 0; int32_t _imm = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(int32_t, _imm, imm);

			reg_read(int32_t, v1, _rs1);
			reg_write(int32_t, _rd, v1 + _imm);
		}

		_vmcall void rv_slliw() {
			uint8_t _rd = 0, _rs1 = 0; int32_t v1 = 0; uint32_t _shamt = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint32_t, _shamt, imm);

			reg_read(int32_t, v1, _rs1);

			if ((_shamt >> 5) != 0) {
				CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, (uint64_t)vmcs->vscratch, 1);
			}
			reg_write(int32_t, _rd, v1 << (_shamt & 0x1F));
		}

		_vmcall void rv_srliw() {
			uint8_t _rd = 0, _rs1 = 0; int32_t v1 = 0; uint32_t _shamt = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint32_t, _shamt, imm);

			reg_read(int32_t, v1, _rs1);

			if ((_shamt >> 5) != 0) {
				CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, (uint64_t)vmcs->vscratch, 1);
			}
			reg_write(int32_t, _rd, v1 >> (_shamt & 0x1F));
		}

		_vmcall void rv_sraiw() {
			uint8_t _rd = 0, _rs1 = 0; int32_t v1 = 0; uint32_t _shamt = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint32_t, _shamt, imm);

			reg_read(int32_t, v1, _rs1);

			if ((_shamt >> 5) != 0) {
				CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, (uint64_t)vmcs->vscratch, 1);
			}
			// TODO: this may be wrong to mask
			reg_write(int32_t, _rd, v1 >> (_shamt & 0x1F));
		}

		_vmcall void rv_lb() {
			uint8_t _rd = 0, _rs1 = 0; int32_t _imm = 0; uintptr_t address = 0; int8_t v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(int32_t, _imm, imm);

			reg_read(uintptr_t, address, _rs1);
			address += (intptr_t)_imm;

			mem_read(int8_t, v1, address);
			reg_write(int8_t, _rd, v1);
		}

		_vmcall void rv_lh() {
			uint8_t _rd = 0, _rs1 = 0; int32_t _imm = 0; uintptr_t address = 0; int16_t v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(int32_t, _imm, imm);

			reg_read(uintptr_t, address, _rs1);
			address += (intptr_t)_imm;

			mem_read(int16_t, v1, address);
			reg_write(int16_t, _rd, v1);
		}

		_vmcall void rv_lw() {
			uint8_t _rd = 0, _rs1 = 0; int32_t _imm = 0; uintptr_t address = 0; int32_t v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(int32_t, _imm, imm);

			reg_read(uintptr_t, address, _rs1);
			address += (intptr_t)_imm;

			mem_read(int32_t, v1, address);
			reg_write(int32_t, _rd, v1);
		}

		_vmcall void rv_lbu() {
			uint8_t _rd = 0, _rs1 = 0; int32_t _imm = 0; uintptr_t address = 0; uint8_t v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(int32_t, _imm, imm);

			reg_read(uintptr_t, address, _rs1);
			address += (intptr_t)_imm;

			mem_read(uint8_t, v1, address);
			reg_write(uint8_t, _rd, v1);
		}

		_vmcall void rv_lhu() {
			uint8_t _rd = 0, _rs1 = 0; int32_t _imm = 0; uintptr_t address = 0; uint16_t v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(int32_t, _imm, imm);

			reg_read(uintptr_t, address, _rs1);
			address += (intptr_t)_imm;

			mem_read(uint16_t, v1, address);
			reg_write(uint16_t, _rd, v1);
		}

		_vmcall void rv_lwu() {
			uint8_t _rd = 0, _rs1 = 0; int32_t _imm = 0; uintptr_t address = 0; uint32_t v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(int32_t, _imm, imm);

			reg_read(uintptr_t, address, _rs1);
			address += (intptr_t)_imm;

			mem_read(uint32_t, v1, address);
			reg_write(uint32_t, _rd, v1);
		}

		_vmcall void rv_ld() {
			uint8_t _rd = 0, _rs1 = 0; int32_t _imm = 0; uintptr_t address = 0; int64_t v1 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(int32_t, _imm, imm);

			reg_read(uintptr_t, address, _rs1);
			address += (intptr_t)_imm;

			mem_read(int64_t, v1, address);
			reg_write(int64_t, _rd, v1);
		}

		_vmcall void rv_jalr() {
			uint8_t _rd = 0, _rs1 = 0; int32_t _imm = 0; uintptr_t address = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(int32_t, _imm, imm);

			reg_read(uintptr_t, address, _rs1);
			address += (intptr_t)_imm;
			address &= ~((intptr_t)1);

			reg_write(uintptr_t, _rd, vmcs->pc);
			vmcs->pc = address;

			__debugbreak();

			if (rvm64::mmu::memory_check(vmcs->pc)) {
				CSR_SET_TRAP(vmcs->pc, environment_execute, 0, 0, 0);
			}
			if (PROCESS_MEMORY_OOB(vmcs->pc)) {
				CSR_SET_TRAP(vmcs->pc, environment_call_native, 0, 0, 0);
			}
			reg_read(uintptr_t, vmcs->pc, _rd);
		}

		_vmcall void rv_flq() {
			CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, 0, 1);
		}

		_vmcall void rv_fence() {
			CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, 0, 1);
		}

		_vmcall void rv_fence_i() {
			CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, 0, 1);
		}

		_vmcall void rv_ecall() {
			/*
			   Description
			   Make a request to the supporting execution environment.
			   When executed in U-mode, S-mode, or M-mode, it generates an environment-call-from-U-mode exception,
			   environment-call-from-S-mode exception, or environment-call-from-M-mode exception, respectively, and performs no other operation.

			   Implementation
			   RaiseException(EnvironmentCall)

			   */
			CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, 0, 1);
		}

		_vmcall void rv_ebreak() {
			/*
			   Description
			   Used by debuggers to cause control to be transferred back to a debugging environment.
			   It generates a breakpoint exception and performs no other operation.

			   Implementation
			   RaiseException(Breakpoint)
			   */

			__debugbreak();
		}

		// NOTE: csr operations aren't needed rn.
		_vmcall void rv_csrrw() {
			/*
			   Description
			   Atomically swaps values in the CSRs and integer registers.
			   CSRRW reads the old value of the CSR, zero-extends the value to XLEN bits, then writes it to integer register _rd.
			   The initial value in _rs1 is written to the CSR.
			   If _rd=x0, then the instruction shall not read the CSR and shall not cause any of the side effects that might occur on a CSR read.

			   Implementation
			   t = CSRs[csr]; CSRs[csr] = x[_rs1]; x[_rd] = t
			   */
			CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, 0, 1);
		}

		_vmcall void rv_csrrs() {
			/*
			   Description
			   Reads the value of the CSR, zero-extends the value to XLEN bits, and writes it to integer register _rd.
			   The initial value in integer register _rs1 is treated as a bit mask that specifies bit positions to be set in the CSR.
			   Any bit that is high in _rs1 will cause the corresponding bit to be set in the CSR, if that CSR bit is writable.
			   Other bits in the CSR are unaffected (though CSRs might have side effects when written).

			   Implementation
			   t = CSRs[csr]; CSRs[csr] = t | x[_rs1]; x[_rd] = t
			   */
			CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, 0, 1);
		}

		_vmcall void rv_csrrc() {
			/*
			   Description
			   Reads the value of the CSR, zero-extends the value to XLEN bits, and writes it to integer register _rd.
			   The initial value in integer register _rs1 is treated as a bit mask that specifies bit positions to be cleared in the CSR.
			   Any bit that is high in _rs1 will cause the corresponding bit to be cleared in the CSR, if that CSR bit is writable.
			   Other bits in the CSR are unaffected.

			   Implementation
			   t = CSRs[csr]; CSRs[csr] = t &~x[_rs1]; x[_rd] = t
			   */
			CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, 0, 1);
		}

		_vmcall void rv_csrrwi() {
			/*
			   Description
			   Update the CSR using an XLEN-bit value obtained by zero-extending a 5-bit unsigned immediate (uimm[4:0]) field encoded in the _rs1 field.

			   Implementation
			   x[_rd] = CSRs[csr]; CSRs[csr] = zimm
			   */
			CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, 0, 1);
		}

		_vmcall void rv_csrrsi() {
			/*
			   Description
			   Set CSR bit using an XLEN-bit value obtained by zero-extending a 5-bit unsigned immediate (uimm[4:0]) field encoded in the _rs1 field.

			   Implementation
			   t = CSRs[csr]; CSRs[csr] = t | zimm; x[_rd] = t
			   */
			CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, 0, 1);
		}

		_vmcall void rv_csrrci() {
			/*
			   Description
			   Clear CSR bit using an XLEN-bit value obtained by zero-extending a 5-bit unsigned immediate (uimm[4:0]) field encoded in the _rs1 field.

			   Implementation
			   t = CSRs[csr]; CSRs[csr] = t &~zimm; x[_rd] = t
			   */
			CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, 0, 1);
		}
	}

	namespace rtype {
		_vmcall void rv_scw() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t address = 0; int32_t value = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			mem_read(uintptr_t, address, _rs1);
			reg_read(int32_t, value, _rs2);

			if (rvm64::memory::vm_check_load_rsv(0, address)) {
				rvm64::memory::vm_set_load_rsv(0, address);

				mem_write(int32_t, address, value);
				reg_write(int32_t, _rd, 0);

				rvm64::memory::vm_clear_load_rsv(0);
			} else {
				reg_write(int32_t, _rd, 1);
			}
		}

		_vmcall void rv_scd() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; int64_t value = 0; uintptr_t address = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, address, _rs1);
			reg_read(int64_t, value, _rs2);

			if (!rvm64::memory::vm_check_load_rsv(0, address)) {
				rvm64::memory::vm_set_load_rsv(0, address);

				mem_write(int64_t, address, value);
				reg_write(int64_t, _rd, 0);

				rvm64::memory::vm_clear_load_rsv(0);

			} else {
				reg_write(int64_t, _rd, 1);
			}
		}

		_vmcall void rv_fadd_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; float v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(float, v1, _rs1);
			reg_read(float, v2, _rs2);

			reg_write(float, _rd, (v1 + v2));
		}

		_vmcall void rv_fsub_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; float v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(float, v1, _rs1);
			reg_read(float, v2, _rs2);

			reg_write(float, _rd, (v1 - v2));
		}

		_vmcall void rv_fmul_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; float v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(float, v1, _rs1);
			reg_read(float, v2, _rs2);

			reg_write(float, _rd, (v1 * v2));
		}

		_vmcall void rv_fdiv_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; float v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(float, v1, _rs1);
			reg_read(float, v2, _rs2);

			reg_write(float, _rd, (v1 / v2));
		}


		_vmcall void rv_fsgnj_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; int64_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(int64_t, v1, _rs1);
			reg_read(int64_t, v2, _rs2);

			int64_t s2 = (v2 >> 63) & 1;

			v1 &= ~(1LL << 63);
			v1 |= (s2 << 63);

			reg_write(int64_t, _rd, v1);
		}

		_vmcall void rv_fsgnjn_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; int64_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(int64_t, v1, _rs1);
			reg_read(int64_t, v2, _rs2);

			int64_t s2 = ((v2 >> 63) & 1) ^ 1;

			v1 &= ~(1LL << 63);
			v1 |= (s2 << 63);

			reg_write(int64_t, _rd, v1);
		}

		_vmcall void rv_fsgnjx_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; int64_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(int64_t, v1, _rs1);
			reg_read(int64_t, v2, _rs2);

			int64_t s1 = (v1 >> 63) & 1;
			int64_t s2 = (v2 >> 63) & 1;

			v1 &= ~(1LL << 63);
			v1 |= ((s1 ^ s2) << 63);

			reg_write(int64_t, _rd, v1);
		}

		_vmcall void rv_fmin_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; double v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(double, v1, _rs1);
			reg_read(double, v2, _rs2);

			if (is_nan(v1)) {
				reg_write(double, _rd, v2);
			} else if (is_nan(v2)) {
				reg_write(double, _rd, v1);
			} else {
				reg_write(double, _rd, (v1 > v2) ? v2 : v1);
			}
		}

		_vmcall void rv_fmax_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; double v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(double, v1, _rs1);
			reg_read(double, v2, _rs2);

			if (is_nan(v1)) {
				reg_write(double, _rd, v2);
			} else if (is_nan(v2)) {
				reg_write(double, _rd, v1);
			} else {
				reg_write(double, _rd, (v1 > v2) ? v1 : v2);
			}
		}

		_vmcall void rv_feq_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; double v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(double, v1, _rs1);
			reg_read(double, v2, _rs2);

			if (is_nan(v1) || is_nan(v2)) {
				reg_write(bool, _rd, false);
				return;
			}
			reg_write(bool, _rd, (v1 == v2));
		}

		_vmcall void rv_flt_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; double v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(double, v1, _rs1);
			reg_read(double, v2, _rs2);

			if (is_nan(v1) || is_nan(v2)) {
				reg_write(bool, _rd, false);
				return;
			}
			reg_write(bool, _rd, (v1 < v2));
		}

		_vmcall void rv_fle_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; double v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(double, v1, _rs1);
			reg_read(double, v2, _rs2);

			if (is_nan(v1) || is_nan(v2)) {
				reg_write(bool, _rd, false);
				return;
			}
			reg_write(bool, _rd, (v1 <= v2));
		}

		_vmcall void rv_addw() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; int32_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(int32_t, v1, _rs1);
			reg_read(int32_t, v2, _rs2);

			reg_write(int64_t, _rd, (int64_t)(v1 + v2));
		}

		_vmcall void rv_subw() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; int32_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(int32_t, v1, _rs1);
			reg_read(int32_t, v2, _rs2);

			reg_write(int64_t, _rd, (int64_t)(v1 - v2));
		}

		_vmcall void rv_mulw() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; int32_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(int32_t, v1, _rs1);
			reg_read(int32_t, v2, _rs2);

			reg_write(int64_t, _rd, (int64_t)(v1 * v2));
		}

		_vmcall void rv_srlw() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; int32_t v1 = 0; uint32_t v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(int32_t, v1, _rs1);
			reg_read(uint32_t, v2, _rs2);

			reg_write(int32_t, _rd, (v1 >> (v2 & 0x1F)));
		}

		_vmcall void rv_sraw() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; int32_t v1 = 0; uint32_t v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(int32_t, v1, _rs1);
			reg_read(uint32_t, v2, _rs2);

			reg_write(int32_t, _rd, (v1 >> (v2 & 0x1F)));
		}

		_vmcall void rv_divuw() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uint32_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uint32_t, v1, _rs1);
			reg_read(uint32_t, v2, _rs2);

			reg_write(uint32_t, _rd, (v1 / v2));
		}

		_vmcall void rv_sllw() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; int32_t v1 = 0; uint32_t v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(int32_t, v1, _rs1);
			reg_read(int32_t, v2, _rs2);

			reg_write(int32_t, _rd, (v1 << (v2 & 0x1F)));
		}

		_vmcall void rv_divw() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; int32_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(int32_t, v1, _rs1);
			reg_read(int32_t, v2, _rs2);

			reg_write(int32_t, _rd, (v1 / v2));
		}

		_vmcall void rv_remw() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; int32_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(int32_t, v1, _rs1);
			reg_read(int32_t, v2, _rs2);

			reg_write(int32_t, _rd, (v1 % v2));
		}

		_vmcall void rv_remuw() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uint32_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uint32_t, v1, _rs1);
			reg_read(uint32_t, v2, _rs2);

			reg_write(uint32_t, _rd, (v1 % v2));
		}

		_vmcall void rv_add() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; int32_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(int32_t, v1, _rs1);
			reg_read(int32_t, v2, _rs2);

			reg_write(int32_t, _rd, (v1 + v2));
		}

		_vmcall void rv_sub() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; int32_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(int32_t, v1, _rs1);
			reg_read(int32_t, v2, _rs2);

			reg_write(int32_t, _rd, (v1 - v2));
		}

		_vmcall void rv_mul() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; int32_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(int32_t, v1, _rs1);
			reg_read(int32_t, v2, _rs2);

			reg_write(int32_t, _rd, (v1 * v2));
		}

		_vmcall void rv_sll() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; int32_t v1 = 0; uint32_t v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(int32_t, _rs1, v1);
			reg_read(int32_t, _rs2, v2);

			reg_write(int32_t, _rd, (v1 << (v2 & 0x1F)));
		}

		_vmcall void rv_mulh() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; intptr_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(intptr_t, v1, _rs1);
			reg_read(intptr_t, v2, _rs2);

#if UINTPTR_MAX == 0xFFFFFFFF
			int64_t result = (int64_t)v1 * (int64_t)v2;
			reg_write(int32_t, _rd, (result >> 32));

#elif UINTPTR_MAX == 0xFFFFFFFFFFFFFFFF
			__int128 result = (__int128)v1 * (__int128)v2;
			reg_write(int64_t, _rd, (result >> 64));

#endif
		}

		_vmcall void rv_slt() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; intptr_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(intptr_t, v1, _rs1);
			reg_read(intptr_t, v2, _rs2);

			reg_write(intptr_t, _rd, ((v1 < v2) ? 1 : 0));
		}

		_vmcall void rv_mulhsu() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; intptr_t v1 = 0; uintptr_t v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(intptr_t, v1, _rs1);
			reg_read(uintptr_t, v2, _rs2);

#if UINTPTR_MAX == 0xFFFFFFFF
			int64_t result = (int64_t)(int32_t)v1 * (uint64_t)(uint32_t)v2;
			reg_write(int32_t, _rd, (result >> 32));

#elif UINTPTR_MAX == 0xFFFFFFFFFFFFFFFF
			__int128 result = (__int128) (int64_t) v1 * (__uint128_t) (uint64_t) v2;
			reg_write(int64_t, _rd, (result >> 64));
#endif
		}

		_vmcall void rv_sltu() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, v1, _rs1);
			reg_read(uintptr_t, v2, _rs2);

			reg_write(uintptr_t, _rd, ((v1 < v2) ? 1 : 0));
		}

		_vmcall void rv_mulhu() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, v1, _rs1);
			reg_read(uintptr_t, v2, _rs2);

			uintptr_t result = v1 * v2;

#if UINTPTR_MAX == 0xFFFFFFFF
			reg_write(uintptr_t, _rd, (result >> 16));
#elif UINTPTR_MAX == 0xFFFFFFFFFFFFFFFF
			reg_write(uintptr_t, _rd, (result >> 32));
#endif
		}

		_vmcall void rv_xor() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, v1, _rs1);
			reg_read(uintptr_t, v2, _rs2);

			reg_write(uintptr_t, _rd, (v1 ^ v2));
		}

		_vmcall void rv_div() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, v1, _rs1);
			reg_read(uintptr_t, v2, _rs2);

			reg_write(uintptr_t, _rd, (v1 / v2));
		}

		_vmcall void rv_srl() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t v1 = 0; uint32_t v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, v1, _rs1);
			reg_read(uint32_t, v2, _rs2);

			reg_write(uintptr_t, _rd, (v1 >> (v2 & 0x1F)));
		}

		_vmcall void rv_sra() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; intptr_t v1 = 0; uint32_t v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(intptr_t, v1, _rs1);
			reg_read(uint32_t, v2, _rs2);

			reg_write(intptr_t, _rd, (v1 >> (v2 & 0x1F)));
		}

		_vmcall void rv_divu() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, v1, _rs1);
			reg_read(uintptr_t, v2, _rs2);

			if (v2 == 0) {
				reg_write(uintptr_t, _rd, 0);
			} else {
				reg_write(uintptr_t, _rd, (v1 / v2));
			}
		}

		_vmcall void rv_or() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; intptr_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(intptr_t, _rs1, v1);
			reg_read(intptr_t, _rs2, v2);

			reg_write(intptr_t, _rd, (v1 | v2));
		}

		_vmcall void rv_rem() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; intptr_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(intptr_t, v1, _rs1);
			reg_read(intptr_t, v2, _rs2);

			if (v2 == 0) {
				reg_write(intptr_t, _rd, 0);
			} else {
				reg_write(intptr_t, _rd, (v1 % v2));
			}
		}

		_vmcall void rv_and() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, v1, _rs1);
			reg_read(uintptr_t, v2, _rs2);

			reg_write(uintptr_t, _rd, (v1 & v2));
		}

		_vmcall void rv_remu() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, v1, _rs1);
			reg_read(uintptr_t, v2, _rs2);

			if (v2 == 0) {
				reg_write(uintptr_t, _rd, 0);
			} else {
				reg_write(uintptr_t, _rd, (v1 % v2));
			}
		}

		_vmcall void rv_amoswap_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t address = 0; int64_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, address, _rs1);
			reg_read(int64_t, v2, _rs2);

			WaitForSingleObject(vmcs_mutex, INFINITE);

			mem_read(int64_t, v1, address);
			mem_write(int64_t, address, v2);
			reg_write(int64_t, _rd, v1);

			ReleaseMutex(vmcs_mutex);
		}

		_vmcall void rv_amoadd_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t address = 0; int64_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, address, _rs1);
			reg_read(int64_t, v2, _rs2);

			WaitForSingleObject(vmcs_mutex, INFINITE);

			mem_read(int64_t, v1, address);
			mem_write(int64_t, address, (v1 + v2));
			reg_write(int64_t, _rd, v1);

			ReleaseMutex(vmcs_mutex);
		}

		_vmcall void rv_amoxor_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t address = 0; int64_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, address, _rs1);
			reg_read(int64_t, v2, _rs2);

			WaitForSingleObject(vmcs_mutex, INFINITE);

			mem_read(int64_t, v1, address);
			mem_write(int64_t, address, (v1 ^ v2));
			reg_write(int64_t, _rd, v1);

			ReleaseMutex(vmcs_mutex);
		}

		_vmcall void rv_amoand_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t address = 0; int64_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, address, _rs1);
			reg_read(int64_t, v2, _rs2);

			WaitForSingleObject(vmcs_mutex, INFINITE);

			mem_read(int64_t, v1, address);
			mem_write(int64_t, address, (v1 & v2));
			reg_write(int64_t, _rd, v1);

			ReleaseMutex(vmcs_mutex);
		}

		_vmcall void rv_amoor_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t address = 0; int64_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, address, _rs1);
			reg_read(int64_t, v2, _rs2);

			WaitForSingleObject(vmcs_mutex, INFINITE);

			mem_read(int64_t, v1, address);
			mem_write(int64_t, address, (v1 | v2));
			reg_write(int64_t, _rd, v1);

			ReleaseMutex(vmcs_mutex);
		}

		_vmcall void rv_amomin_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t address = 0; int64_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, address, _rs1);
			reg_read(uint64_t, v2, _rs2);

			WaitForSingleObject(vmcs_mutex, INFINITE);

			mem_read(int64_t, v1, address);
			mem_write(int64_t, address, (v1 < v2 ? v1 : v2));
			reg_write(uint64_t, _rd, v1);

			ReleaseMutex(vmcs_mutex);
		}

		_vmcall void rv_amomax_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t address = 0; int64_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, address, _rs1);
			reg_read(int64_t, v2, _rs2);

			WaitForSingleObject(vmcs_mutex, INFINITE);

			mem_read(int64_t, v1, address);
			mem_write(int64_t, address, (v1 < v2 ? v2 : v1));
			reg_write(int64_t, _rd, v1);

			ReleaseMutex(vmcs_mutex);
		}

		_vmcall void rv_amominu_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t address = 0; uint64_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, _rs1, address);
			reg_read(uint64_t, _rs2, v2);

			WaitForSingleObject(vmcs_mutex, INFINITE);

			mem_read(uint64_t, v1, address);
			mem_write(uint64_t, address, (v1 < v2 ? v1 : v2));
			reg_write(uint64_t, _rd, v1);

			ReleaseMutex(vmcs_mutex);
		}

		_vmcall void rv_amomaxu_d() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t address = 0; uint64_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, address, _rs1);
			reg_read(uint64_t, v2, _rs2);

			WaitForSingleObject(vmcs_mutex, INFINITE);

			mem_read(uint64_t, v1, address);
			mem_write(uint64_t, address, (v1 < v2 ? v2 : v1));
			reg_write(uint64_t, _rd, v1);

			ReleaseMutex(vmcs_mutex);
		}

		_vmcall void rv_amoswap_w() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t address = 0; int32_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, address, _rs1);
			reg_read(int32_t, v2, _rs2);

			WaitForSingleObject(vmcs_mutex, INFINITE);

			mem_read(int32_t, v1, address);
			mem_write(int32_t, address, v2);
			reg_write(int32_t, _rd, v1);

			ReleaseMutex(vmcs_mutex);
		}

		_vmcall void rv_amoadd_w() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t address = 0; int32_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, address, _rs1);
			reg_read(int32_t, v2, _rs2);

			WaitForSingleObject(vmcs_mutex, INFINITE);

			mem_read(int32_t, v1, address);
			mem_write(int32_t, address, (v1 + v2));
			reg_write(int32_t, _rd, v1);

			ReleaseMutex(vmcs_mutex);
		}

		_vmcall void rv_amoxor_w() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t address = 0; int32_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, address, _rs1);
			reg_read(int32_t, v2, _rs2);

			WaitForSingleObject(vmcs_mutex, INFINITE);

			mem_read(int32_t, v1, address);
			mem_write(int32_t, address, (v1 ^ v2));
			reg_write(int32_t, _rd, v1);

			ReleaseMutex(vmcs_mutex);
		}

		_vmcall void rv_amoand_w() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t address = 0; int32_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, address, _rs1);
			reg_read(int32_t, v2, _rs2);

			WaitForSingleObject(vmcs_mutex, INFINITE);

			mem_read(int32_t, v1, address);
			mem_write(int32_t, address, (v1 & v2));
			reg_write(int32_t, _rd, v1);

			ReleaseMutex(vmcs_mutex);
		}

		_vmcall void rv_amoor_w() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t address = 0; int32_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, address, _rs1);
			reg_read(int32_t, v2, _rs2);

			WaitForSingleObject(vmcs_mutex, INFINITE);

			mem_read(int32_t, v1, address);
			mem_write(int32_t, address, (v1 | v2));
			reg_write(int32_t, _rd, v1);

			ReleaseMutex(vmcs_mutex);
		}

		_vmcall void rv_amomin_w() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t address = 0; int32_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, address, _rs1);
			reg_read(int32_t, v2, _rs2);

			WaitForSingleObject(vmcs_mutex, INFINITE);

			mem_read(int32_t, v1, address);
			mem_write(int32_t, address, (v1 < v2 ? v1 : v2));
			reg_write(int32_t, _rd, v1);

			ReleaseMutex(vmcs_mutex);
		}

		_vmcall void rv_amomax_w() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t address = 0; int32_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, address, _rs1);
			reg_read(int32_t, v2, _rs2);

			WaitForSingleObject(vmcs_mutex, INFINITE);

			mem_read(int32_t, v1, address);
			mem_write(int32_t, address, (v1 < v2 ? v2 : v1));
			reg_write(int32_t, _rd, v1);

			ReleaseMutex(vmcs_mutex);
		}

		_vmcall void rv_amominu_w() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t address = 0; uint32_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, address, _rs1);
			reg_read(uint32_t, v2, _rs2);

			WaitForSingleObject(vmcs_mutex, INFINITE);

			mem_read(uint32_t, v1, address);
			mem_write(uint32_t, address, (v1 < v2 ? v1 : v2));
			reg_write(uint32_t, _rd, v1);

			ReleaseMutex(vmcs_mutex);
		}

		_vmcall void rv_amomaxu_w() {
			uint8_t _rd = 0, _rs1 = 0, _rs2 = 0; uintptr_t address = 0; uint32_t v1 = 0, v2 = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);

			reg_read(uintptr_t, address, _rs1);
			reg_read(uint32_t, v2, _rs2);

			WaitForSingleObject(vmcs_mutex, INFINITE);

			mem_read(uint32_t, v1, address);
			mem_write(uint32_t, address, (v1 < v2 ? v2 : v1));
			reg_write(uint32_t, _rd, v1);

			ReleaseMutex(vmcs_mutex);
		}
	}

	namespace utype {
		_vmcall void rv_lui() {
			uint8_t _rd = 0; int32_t _imm = 0;

			scr_read(uint32_t, _rd, rd);
			scr_read(int32_t, _imm, imm);
			reg_write(int32_t, _rd, _imm);
		}

		_vmcall void rv_auipc() {
			uint8_t _rd = 0; int32_t _imm = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(int32_t, _imm, imm);
			reg_write(int64_t, _rd, (int64_t)vmcs->pc + _imm);
		}
	}

	namespace jtype {
		_vmcall void rv_jal() {
			uint8_t _rd = 0; intptr_t offset = 0;

			scr_read(uint8_t, _rd, rd);
			scr_read(intptr_t, offset, imm);
			reg_write(uintptr_t, _rd, vmcs->pc + 4);

			vmcs->pc += offset;
			CSR_SET_TRAP(nullptr, environment_branch, 0, 0, 0);
		}
	}

	namespace btype {
		_vmcall void rv_beq() {
			uint8_t _rs1 = 0, _rs2 = 0; int32_t v1 = 0, v2 = 0; intptr_t offset = 0;

			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);
			scr_read(intptr_t, offset, imm);

			reg_read(int32_t, v1, _rs1);
			reg_read(int32_t, v2, _rs2);

			if (v1 == v2) {
				vmcs->pc += offset;
				CSR_SET_TRAP(nullptr, environment_branch, 0, 0, 0);
			}
		}

		_vmcall void rv_bne() {
			uint8_t _rs1 = 0, _rs2 = 0; int32_t v1 = 0, v2 = 0; intptr_t offset = 0;

			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);
			scr_read(intptr_t, offset, imm);

			reg_read(int32_t, v1, _rs1);
			reg_read(int32_t, v2, _rs2);

			if (v1 != v2) {
				vmcs->pc += offset;
				CSR_SET_TRAP(nullptr, environment_branch, 0, 0, 0);
			}
		}

		_vmcall void rv_blt() {
			uint8_t _rs1 = 0, _rs2 = 0; int32_t v1 = 0, v2 = 0; intptr_t offset = 0;

			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);
			scr_read(intptr_t, offset, imm);

			reg_read(int32_t, v1, _rs1);
			reg_read(int32_t, v2, _rs2);

			if (v1 < v2) {
				vmcs->pc += offset;
				CSR_SET_TRAP(nullptr, environment_branch, 0, 0, 0);
			}
		}

		_vmcall void rv_bge() {
			uint8_t _rs1 = 0, _rs2 = 0; int32_t v1 = 0, v2 = 0; intptr_t offset = 0;

			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);
			scr_read(intptr_t, offset, imm);

			reg_read(int32_t, v1, _rs1);
			reg_read(int32_t, v2, _rs2);

			if (v1 >= v2) {
				vmcs->pc += offset;
				CSR_SET_TRAP(nullptr, environment_branch, 0, 0, 0);
			}
		}

		_vmcall void rv_bltu() {
			uint8_t _rs1 = 0, _rs2 = 0; uint32_t v1 = 0, v2 = 0; intptr_t offset = 0;

			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);
			scr_read(intptr_t, offset, imm);

			reg_read(uint32_t, v1, _rs1);
			reg_read(uint32_t, v2, _rs2);

			if (v1 < v2) {
				vmcs->pc += offset;
				CSR_SET_TRAP(nullptr, environment_branch, 0, 0, 0);
			}
		}

		_vmcall void rv_bgeu() {
			uint8_t _rs1 = 0, _rs2 = 0; uint32_t v1 = 0, v2 = 0; intptr_t offset = 0;

			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);
			scr_read(intptr_t, offset, imm);

			reg_read(uint32_t, v1, _rs1);
			reg_read(uint32_t, v2, _rs2);

			if (v1 >= v2) {
				vmcs->pc += offset;
				CSR_SET_TRAP(nullptr, environment_branch, 0, 0, 0);
			}
		}
	}

	namespace stype {
		_vmcall void rv_sb() {
			uint8_t _rs1 = 0, _rs2 = 0; int32_t _imm = 0; uintptr_t address = 0; uint8_t v1 = 0;

			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);
			scr_read(int32_t, _imm, imm);

			reg_read(uintptr_t, address, _rs1);
			reg_read(int8_t, v1, _rs2);

			address += (intptr_t)_imm;
			mem_write(uint8_t, address, v1);
		}

		_vmcall void rv_sh() {
			uint8_t _rs1 = 0, _rs2 = 0; int32_t _imm = 0; uintptr_t address = 0; uint16_t v1 = 0;

			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);
			scr_read(int32_t, _imm, imm);

			reg_read(uintptr_t, address, _rs1);
			reg_read(uint16_t, v1, _rs2);

			address += (intptr_t)_imm;
			mem_write(uint16_t, address, v1);
		}

		_vmcall void rv_sw() {
			uint8_t _rs1 = 0, _rs2 = 0; int32_t _imm = 0; uintptr_t address = 0; uint32_t v1 = 0;

			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);
			scr_read(int32_t, _imm, imm);

			reg_read(uintptr_t, address, _rs1);
			reg_read(uint32_t, v1, _rs2);

			address += (intptr_t)_imm;
			mem_write(uint32_t, address, v1);
		}

		_vmcall void rv_sd() {
			uint8_t _rs1 = 0, _rs2 = 0; int32_t _imm = 0; uintptr_t address = 0; uint64_t v1 = 0;

			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);
			scr_read(int32_t, _imm, imm);

			reg_read(uintptr_t, address, _rs1);
			reg_read(uint64_t, v1, _rs2);

			address += (intptr_t)_imm;
			mem_write(uint64_t, address, v1);
		}

		_vmcall void rv_fsw() {
			uint8_t _rs1 = 0, _rs2 = 0; int32_t _imm = 0; uintptr_t address = 0; float v1 = 0;

			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);
			scr_read(int32_t, _imm, imm);

			reg_read(uintptr_t, address, _rs1);
			reg_read(float, v1, _rs2);

			address += (intptr_t)_imm;
			mem_write(float, address, v1);
		}

		_vmcall void rv_fsd() {
			uint8_t _rs1 = 0, _rs2 = 0; int32_t _imm = 0; uintptr_t address = 0; double v1 = 0;

			scr_read(uint8_t, _rs1, rs1);
			scr_read(uint8_t, _rs2, rs2);
			scr_read(int32_t, _imm, imm);

			reg_read(uintptr_t, address, _rs1);
			reg_read(uint64_t, v1, _rs2);

			address += (intptr_t)_imm;
			mem_write(double, address, v1);
		}
	}

	namespace r4type {};
};

_rdata const uintptr_t dispatch_table[256] = {
#define ENCRYPT(op) rvm64::crypt::encrypt_ptr((uintptr_t)(op))

    // ITYPE
    ENCRYPT(rvm64::operations::itype::rv_addi), ENCRYPT(rvm64::operations::itype::rv_slti),
    ENCRYPT(rvm64::operations::itype::rv_sltiu), ENCRYPT(rvm64::operations::itype::rv_xori),
    ENCRYPT(rvm64::operations::itype::rv_ori), ENCRYPT(rvm64::operations::itype::rv_andi),
    ENCRYPT(rvm64::operations::itype::rv_slli), ENCRYPT(rvm64::operations::itype::rv_srli),
    ENCRYPT(rvm64::operations::itype::rv_srai), ENCRYPT(rvm64::operations::itype::rv_addiw),
    ENCRYPT(rvm64::operations::itype::rv_slliw), ENCRYPT(rvm64::operations::itype::rv_srliw),
    ENCRYPT(rvm64::operations::itype::rv_sraiw), ENCRYPT(rvm64::operations::itype::rv_lb),
    ENCRYPT(rvm64::operations::itype::rv_lh), ENCRYPT(rvm64::operations::itype::rv_lw),
    ENCRYPT(rvm64::operations::itype::rv_lbu), ENCRYPT(rvm64::operations::itype::rv_lhu),
    ENCRYPT(rvm64::operations::itype::rv_lwu), ENCRYPT(rvm64::operations::itype::rv_ld),
    ENCRYPT(rvm64::operations::itype::rv_flq), ENCRYPT(rvm64::operations::itype::rv_fence),
    ENCRYPT(rvm64::operations::itype::rv_fence_i), ENCRYPT(rvm64::operations::itype::rv_jalr),
    ENCRYPT(rvm64::operations::itype::rv_ecall), ENCRYPT(rvm64::operations::itype::rv_ebreak),
    ENCRYPT(rvm64::operations::itype::rv_csrrw), ENCRYPT(rvm64::operations::itype::rv_csrrs),
    ENCRYPT(rvm64::operations::itype::rv_csrrc), ENCRYPT(rvm64::operations::itype::rv_csrrwi),
    ENCRYPT(rvm64::operations::itype::rv_csrrsi), ENCRYPT(rvm64::operations::itype::rv_csrrci),
    ENCRYPT(rvm64::operations::itype::rv_fclass_d), ENCRYPT(rvm64::operations::itype::rv_lrw),
    ENCRYPT(rvm64::operations::itype::rv_lrd), ENCRYPT(rvm64::operations::itype::rv_fmv_d_x),
    ENCRYPT(rvm64::operations::itype::rv_fcvt_s_d), ENCRYPT(rvm64::operations::itype::rv_fcvt_d_s),
    ENCRYPT(rvm64::operations::itype::rv_fcvt_w_d), ENCRYPT(rvm64::operations::itype::rv_fcvt_wu_d),
    ENCRYPT(rvm64::operations::itype::rv_fcvt_d_w), ENCRYPT(rvm64::operations::itype::rv_fcvt_d_wu),

    // RTYPE
    ENCRYPT(rvm64::operations::rtype::rv_fadd_d), ENCRYPT(rvm64::operations::rtype::rv_fsub_d),
    ENCRYPT(rvm64::operations::rtype::rv_fmul_d), ENCRYPT(rvm64::operations::rtype::rv_fdiv_d),
    ENCRYPT(rvm64::operations::rtype::rv_fsgnj_d), ENCRYPT(rvm64::operations::rtype::rv_fsgnjn_d),
    ENCRYPT(rvm64::operations::rtype::rv_fsgnjx_d), ENCRYPT(rvm64::operations::rtype::rv_fmin_d),
    ENCRYPT(rvm64::operations::rtype::rv_fmax_d), ENCRYPT(rvm64::operations::rtype::rv_feq_d),
    ENCRYPT(rvm64::operations::rtype::rv_flt_d), ENCRYPT(rvm64::operations::rtype::rv_fle_d),
    ENCRYPT(rvm64::operations::rtype::rv_scw), ENCRYPT(rvm64::operations::rtype::rv_amoswap_w),
    ENCRYPT(rvm64::operations::rtype::rv_amoadd_w), ENCRYPT(rvm64::operations::rtype::rv_amoxor_w),
    ENCRYPT(rvm64::operations::rtype::rv_amoand_w), ENCRYPT(rvm64::operations::rtype::rv_amoor_w),
    ENCRYPT(rvm64::operations::rtype::rv_amomin_w), ENCRYPT(rvm64::operations::rtype::rv_amomax_w),
    ENCRYPT(rvm64::operations::rtype::rv_amominu_w), ENCRYPT(rvm64::operations::rtype::rv_amomaxu_w),
    ENCRYPT(rvm64::operations::rtype::rv_scd), ENCRYPT(rvm64::operations::rtype::rv_amoswap_d),
    ENCRYPT(rvm64::operations::rtype::rv_amoadd_d), ENCRYPT(rvm64::operations::rtype::rv_amoxor_d),
    ENCRYPT(rvm64::operations::rtype::rv_amoand_d), ENCRYPT(rvm64::operations::rtype::rv_amoor_d),
    ENCRYPT(rvm64::operations::rtype::rv_amomin_d), ENCRYPT(rvm64::operations::rtype::rv_amomax_d),
    ENCRYPT(rvm64::operations::rtype::rv_amominu_d), ENCRYPT(rvm64::operations::rtype::rv_amomaxu_d),
    ENCRYPT(rvm64::operations::rtype::rv_addw), ENCRYPT(rvm64::operations::rtype::rv_subw),
    ENCRYPT(rvm64::operations::rtype::rv_mulw), ENCRYPT(rvm64::operations::rtype::rv_srlw),
    ENCRYPT(rvm64::operations::rtype::rv_sraw), ENCRYPT(rvm64::operations::rtype::rv_divuw),
    ENCRYPT(rvm64::operations::rtype::rv_sllw), ENCRYPT(rvm64::operations::rtype::rv_divw),
    ENCRYPT(rvm64::operations::rtype::rv_remw), ENCRYPT(rvm64::operations::rtype::rv_remuw),
    ENCRYPT(rvm64::operations::rtype::rv_add), ENCRYPT(rvm64::operations::rtype::rv_sub),
    ENCRYPT(rvm64::operations::rtype::rv_mul), ENCRYPT(rvm64::operations::rtype::rv_sll),
    ENCRYPT(rvm64::operations::rtype::rv_mulh), ENCRYPT(rvm64::operations::rtype::rv_slt),
    ENCRYPT(rvm64::operations::rtype::rv_mulhsu), ENCRYPT(rvm64::operations::rtype::rv_sltu),
    ENCRYPT(rvm64::operations::rtype::rv_mulhu), ENCRYPT(rvm64::operations::rtype::rv_xor),
    ENCRYPT(rvm64::operations::rtype::rv_div), ENCRYPT(rvm64::operations::rtype::rv_srl),
    ENCRYPT(rvm64::operations::rtype::rv_sra), ENCRYPT(rvm64::operations::rtype::rv_divu),
    ENCRYPT(rvm64::operations::rtype::rv_or), ENCRYPT(rvm64::operations::rtype::rv_rem),
    ENCRYPT(rvm64::operations::rtype::rv_and), ENCRYPT(rvm64::operations::rtype::rv_remu),

    // STYPE
    ENCRYPT(rvm64::operations::stype::rv_sb), ENCRYPT(rvm64::operations::stype::rv_sh),
    ENCRYPT(rvm64::operations::stype::rv_sw), ENCRYPT(rvm64::operations::stype::rv_sd),
    ENCRYPT(rvm64::operations::stype::rv_fsw), ENCRYPT(rvm64::operations::stype::rv_fsd),

    // BTYPE
    ENCRYPT(rvm64::operations::btype::rv_beq), ENCRYPT(rvm64::operations::btype::rv_bne),
    ENCRYPT(rvm64::operations::btype::rv_blt), ENCRYPT(rvm64::operations::btype::rv_bge),
    ENCRYPT(rvm64::operations::btype::rv_bltu), ENCRYPT(rvm64::operations::btype::rv_bgeu),

    // UTYPE/JTYPE
    ENCRYPT(rvm64::operations::utype::rv_lui), ENCRYPT(rvm64::operations::utype::rv_auipc),
    ENCRYPT(rvm64::operations::jtype::rv_jal)

#undef ENCRYPT
};
#endif // VMCODE_H
