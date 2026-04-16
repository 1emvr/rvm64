#ifndef VMCODE_H
#define VMCODE_H
#include <stdarg.h>

#include "../include/vmmain.hpp"
#include "../include/vmmem.hpp"

#include "vmutils.hpp"
#include "vmcrypt.hpp"
#include "vmrwx.hpp"
#include "vmmu.hpp"

// TODO: Change reg read/write from macros to functions for size.

VMCALL VOID Decode (const UINT32 opcode) {
	UINT8 decoded = 0;
	UINT8 opcode7 = opcode & 0x7F;

	for (int idx = 0; idx < sizeof(encoding); idx++) {
		if (encoding[idx].mask == opcode7) {
			decoded = encoding[idx].type;
			break;
		}
	}
	if (!decoded) {
		CSR_SET_TRAP (Vmcs->Gpr->Pc, illegal_instruction, 0, opcode, 1);
	}

	switch(decoded) {
		case itype: 
			{
				UINT8 func3 = (opcode >> 12) & 0x7;
				ScrWrite (UINT8, screnum::rd, (opcode >> 7) & 0x1F);
				ScrWrite (UINT8, screnum::rs1, (opcode >> 15) & 0x1F);

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
								case 0b000: { ScrWrite (INT32, imm, imm_i(opcode)); unwrap_opcall(_rv_addi); break; }
								case 0b010: { ScrWrite (INT32, imm, imm_i(opcode)); unwrap_opcall(_rv_slti); break; }
								case 0b011: { ScrWrite (INT32, imm, imm_i(opcode)); unwrap_opcall(_rv_sltiu); break; }
								case 0b100: { ScrWrite (INT32, imm, imm_i(opcode)); unwrap_opcall(_rv_xori); break; }
								case 0b110: { ScrWrite (INT32, imm, imm_i(opcode)); unwrap_opcall(_rv_ori);  break; }
								case 0b111: { ScrWrite (INT32, imm, imm_i(opcode)); unwrap_opcall(_rv_andi); break; }
								case 0b001: { ScrWrite (INT32, imm, shamt_i(opcode)); unwrap_opcall(_rv_slli); break; }
								case 0b101: {
												UINT8 func7 = (opcode >> 25) & 0x7F; // NOTE: "opcode >> 24" (?) Not sure 
												switch(func7) {
													case 0b0000000: { ScrWrite (INT32, imm, shamt_i(opcode)); unwrap_opcall(_rv_srli); break; }
													case 0b0100000: { ScrWrite (INT32, imm, shamt_i(opcode)); unwrap_opcall(_rv_srai); break; }
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
								case 0b000: { ScrWrite (INT32, imm, imm_i(opcode)); unwrap_opcall(_rv_addiw); break; }
								case 0b001: { ScrWrite (INT32, imm, shamt_i(opcode)); unwrap_opcall(_rv_slliw); break; }
								case 0b101: 
											{
												UINT8 func7 = (opcode >> 25) & 0x7F;
												switch(func7) {
													case 0b0000000: { ScrWrite (INT32, imm, shamt_i(opcode)); unwrap_opcall(_rv_srliw); break; }
													case 0b0100000: { ScrWrite (INT32, imm, shamt_i(opcode)); unwrap_opcall(_rv_sraiw); break; }
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
								case 0b000: { ScrWrite (INT32, imm, imm_i(opcode)); unwrap_opcall(_rv_lb); break;  }
								case 0b001: { ScrWrite (INT32, imm, imm_i(opcode)); unwrap_opcall(_rv_lh); break;  }
								case 0b010: { ScrWrite (INT32, imm, imm_i(opcode)); unwrap_opcall(_rv_lw); break;  }
								case 0b100: { ScrWrite (INT32, imm, imm_i(opcode)); unwrap_opcall(_rv_lbu); break; }
								case 0b101: { ScrWrite (INT32, imm, imm_i(opcode)); unwrap_opcall(_rv_lhu); break; }
								case 0b110: { ScrWrite (INT32, imm, imm_i(opcode)); unwrap_opcall(_rv_lwu); break; }
								case 0b011: { ScrWrite (INT32, imm, imm_i(opcode)); unwrap_opcall(_rv_ld); break;  }
								default: break;
							}
							break;
						}
					case 0b1100111:
						{
							switch(func3) {
								case 0b000: { ScrWrite (INT32, imm, imm_i(opcode)); unwrap_opcall(_rv_jalr); break; }
							}
						}
					default: break;
				}
				break;
			}

		case rtype: 
			{
				ScrWrite (UINT8, screnum::rd, (opcode >> 7) & 0x1F);
				ScrWrite (UINT8, screnum::rs1, (opcode >> 15) & 0x1F);
				ScrWrite (UINT8, screnum::rs2, (opcode >> 20) & 0x1F);

				switch(opcode7) {
					case 0b1010011: 
						{
							UINT8 func7 = (opcode >> 25) & 0x7F;
							switch(func7) {
								case 0b0000001: { unwrap_opcall(_rv_fadd_d); break; }
								case 0b0000101: { unwrap_opcall(_rv_fsub_d); break; }
								case 0b0001001: { unwrap_opcall(_rv_fmul_d); break; }
								case 0b0001101: { unwrap_opcall(_rv_fdiv_d); break; }
								case 0b1111001: { unwrap_opcall(_rv_fmv_d_x); break; }
								case 0b0100000: 
												{
													UINT8 fcvt_mask = (opcode >> 20) & 0x1F;
													switch(fcvt_mask) {
														case 0b00001: { unwrap_opcall(_rv_fcvt_s_d); break; }
														default: break;
													}
													break;
												}
								case 0b0100001: 
												{
													UINT8 fcvt_mask = (opcode >> 20) & 0x1F;
													switch(fcvt_mask) {
														case 0b00000: { unwrap_opcall(_rv_fcvt_d_s); break; }
														default: break;
													}
													break;
												}
								case 0b1100001: 
												{
													UINT8 fcvt_mask = (opcode >> 20) & 0x1F;
													switch(fcvt_mask) {
														case 0b00000: { unwrap_opcall(_rv_fcvt_w_d); break; }
														case 0b00001: { unwrap_opcall(_rv_fcvt_wu_d); break; }
														default: break;
													}
													break;
												}
								case 0b1101001: 
												{
													UINT8 fcvt_mask = (opcode >> 20) & 0x1F;
													switch(fcvt_mask) {
														case 0b00000: { unwrap_opcall(_rv_fcvt_d_w); break; }
														case 0b00001: { unwrap_opcall(_rv_fcvt_d_wu); break; }
														default: break;
													}
													break;
												}
								case 0b0010001: 
												{
													UINT8 func3 = (opcode >> 12) & 0x7;
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
													UINT8 func3 = (opcode >> 12) & 0x7;
													switch(func3) {
														case 0b000: { unwrap_opcall(_rv_fmin_d); break; }
														case 0b001: { unwrap_opcall(_rv_fmax_d); break; }
														default: break;
													}
													break;
												}
								case 0b1010001: 
												{
													UINT8 func3 = (opcode >> 12) & 0x7;
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
													UINT8 func3 = (opcode >> 12) & 0x7;
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
							UINT8 func7 = (opcode >> 25) & 0x7F;
							UINT8 func5 = (func7 >> 2) & 0x1F;
							UINT8 func3 = (opcode >> 12) & 0x7;

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
							UINT8 func7 = (opcode >> 25) & 0x7F;
							UINT8 func3 = (opcode >> 12) & 0x7;

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
							UINT8 func7 = (opcode >> 25) & 0x7F;
							UINT8 func3 = (opcode >> 12) & 0x7;

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
				UINT8 func3 = (opcode >> 12) & 0x7;

				ScrWrite (UINT8, screnum::rs2, (opcode >> 20) & 0x1F);
				ScrWrite (UINT8, screnum::rs1, (opcode >> 15) & 0x1F);
				ScrWrite (INT32, imm, imm_s(opcode));

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
				UINT8 func3 = (opcode >> 12) & 0x7;

				ScrWrite (UINT8, screnum::rs2, (opcode >> 20) & 0x1F);
				ScrWrite (UINT8, screnum::rs1, (opcode >> 15) & 0x1F);
				ScrWrite (INT32, imm, imm_b(opcode));

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
				ScrWrite (UINT8, screnum::rd, (opcode >> 7) & 0x1F);
				ScrWrite (INT32, screnum::imm, imm_u(opcode));

				switch(opcode7) {
					case 0b0110111: { unwrap_opcall(_rv_lui); break; }
					case 0b0010111: { unwrap_opcall(_rv_auipc); break; }
					default: break;
				}
				break;
			}

		case jtype:
			{
				ScrWrite (UINT8, screnum::rd, (opcode >> 7) & 0x1F);
				ScrWrite (INT32, screnum::imm, imm_j(opcode));

				switch(opcode7) {
					case 0b1101111: { unwrap_opcall(_rv_jal); break; }
					default: break;
				}
				break;
			}

		default: {
					 CSR_SET_TRAP (Vmcs->Gpr->Pc, illegal_instruction, 0, opcode, 1);
					 break;
				 }
	}
}

	union {
		double d;
		UINT64 u;
	} converter;

	VMCALL bool is_nan(double x) {
		converter.d = x;

		UINT64 exponent = (converter.u & EXPONENT_MASK) >> 52;
		UINT64 fraction = converter.u & FRACTION_MASK;

		return (exponent == 0x7FF) && (fraction != 0);
	}

	namespace itype {
		VMCALL void rv_lrw() {
			UINT8 _rd = 0, _rs1 = 0; UINT_PTR address = 0; INT32 value = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);

			RegRead (UINT_PTR, address, _rs1);

			MemRead (INT32, value, address);
			RegWrite (INT32, _rd, value);
		}

		VMCALL void rv_lrd() {
			UINT8 _rd = 0, _rs1 = 0; UINT_PTR address = 0; INT64 value = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);

			RegRead (UINT_PTR, address, _rs1);

			MemRead (INT64, value, address);
			RegWrite (INT64, _rd, value);
		}

		VMCALL void rv_fmv_d_x() {
			UINT8 _rd = 0, _rs1 = 0; INT64 v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);

			RegRead (INT64, v1, _rs1);
			RegWrite (INT64, _rd, v1);
		}

		VMCALL void rv_fcvt_s_d() {
			UINT8 _rd = 0, _rs1 = 0; float v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);

			RegRead (double, v1, _rs1);
			RegWrite (float, _rd, v1);
		}

		VMCALL void rv_fcvt_d_s() {
			UINT8 _rd = 0, _rs1 = 0; double v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);

			RegRead (float, v1, _rs1);
			RegWrite (double, _rd, v1);
		}

		VMCALL void rv_fcvt_w_d() {
			UINT8 _rd = 0, _rs1 = 0; INT32 v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);

			RegRead (double, v1, _rs1);
			RegWrite (INT32, _rd, v1);
		}

		VMCALL void rv_fcvt_wu_d() {
			UINT8 _rd = 0, _rs1 = 0; UINT32 v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);

			RegRead (double, v1, _rs1);
			RegWrite (UINT32, _rd, v1);
		}

		VMCALL void rv_fcvt_d_w() {
			UINT8 _rd = 0, _rs1 = 0; INT32 v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);

			RegRead (INT32, v1, _rs1);
			RegWrite (double, _rd, v1);
		}

		VMCALL void rv_fcvt_d_wu() {
			UINT8 _rd = 0, _rs1 = 0; UINT32 v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);

			RegRead (UINT32, v1, _rs1);
			RegWrite (double, _rd, v1);
		}

		// NOTE: maybe not even real...
		VMCALL void rv_fclass_d() {
			UINT8 _rd = 0, _rs1 = 0; double v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);

			RegRead (double, v1, _rs1);
			converter.d = v1;

			const UINT64 exponent = (converter.u >> 52) & 0x7FF;
			const UINT64 fraction = converter.u & 0xFFFFFFFFFFFFF;
			const UINT64 sign = converter.u >> 63;

			if (exponent == 0x7FF) {
				if (fraction == 0) {
					if (sign == 0) {
						RegWrite (int, _rd, 0x7); // +inf
					} else {
						RegWrite (int, _rd, 0x0); // -inf
					}
				} else {
					if (fraction & (1LL << 51)) {
						RegWrite (int, _rd, 0x8); // quiet NaN
					} else {
						RegWrite (int, _rd, 0x9); // signaling NaN
					}
				}
			} else if (exponent == 0) {
				if (fraction == 0) {
					if (sign == 0) {
						RegWrite (int, _rd, 0x4); // +0
					} else {
						RegWrite (int, _rd, 0x3); // -0
					}
				} else {
					if (sign == 0) {
						RegWrite (int, _rd, 0x5); // +subnormal
					} else {
						RegWrite (int, _rd, 0x2); // -subnormal
					}
				}
			} else {
				if (sign == 0) {
					RegWrite (int, _rd, 0x6); // +normal
				} else {
					RegWrite (int, _rd, 0x1); // -normal
				}
			}
		}

		// NOTE: immediates are always signed unless there's a bitwise operation
		VMCALL void rv_addi() {
			UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; INT64 v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);
			ScrRead (INT32, _imm, imm);

			RegRead (INT64, v1, _rs1);
			RegWrite (INT64, _rd, (v1 + _imm));
		}

		VMCALL void rv_slti() {
			UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; INT64 v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);
			ScrRead (INT32, _imm, imm);

			RegRead (INT64, v1, _rs1);
			RegWrite (INT64, _rd, ((v1 < _imm) ? 1 : 0));
		}

		VMCALL void rv_sltiu() {
			UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; UINT64 v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);
			ScrRead (INT32, _imm, imm);

			RegRead (UINT64, v1, _rs1);
			RegWrite (UINT64, _rd, ((v1 < (UINT32)_imm) ? 1 : 0));
		}

		VMCALL void rv_xori() {
			UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; INT64 v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);
			ScrRead (INT32, _imm, imm);

			RegRead (INT64, v1, _rs1);
			RegWrite (INT64, _rd, (v1 ^ _imm));
		}

		VMCALL void rv_ori() {
			UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; INT64 v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);
			ScrRead (INT32, _imm, imm);

			RegRead (INT64, v1, _rs1);
			RegWrite (INT64, _rd, (v1 | _imm));
		}

		VMCALL void rv_andi() {
			UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; INT64 v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (INT32, _rs1, rs1);
			ScrRead (INT32, _imm, imm);

			RegRead (INT64, v1, _rs1);
			RegWrite (INT64, _rd, (v1 & _imm));
		}

		VMCALL void rv_slli() {
			UINT8 _rd = 0, _rs1 = 0; UINT32 _shamt = 0; INT64 v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);
			ScrRead (UINT32, _shamt, imm);

			RegRead (UINT64, v1, _rs1);
			RegWrite (UINT64, _rd, (v1 << (_shamt & 0x1F)));
		}

		VMCALL void rv_srli() {
			UINT8 _rd = 0, _rs1 = 0; UINT32 _shamt = 0; UINT64 v1 = 0; 

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);
			ScrRead (UINT32, _shamt, imm);

			RegRead (UINT64, v1, _rs1);
			RegWrite (UINT64, _rd, v1 >> (_shamt & 0x1F));
		}

		VMCALL void rv_srai() {
			UINT8 _rd = 0, _rs1 = 0; UINT32 _shamt = 0; UINT64 v1 = 0; 

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);
			ScrRead (UINT32, _shamt, imm);

			RegRead (UINT64, v1, _rs1);
			RegWrite (UINT64, _rd, v1 >> (_shamt & 0x1F));
		}

		VMCALL void rv_addiw() {
			UINT8 _rd = 0, _rs1 = 0; INT32 v1 = 0; INT32 _imm = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);
			ScrRead (INT32, _imm, imm);

			RegRead (INT32, v1, _rs1);
			RegWrite (INT32, _rd, v1 + _imm);
		}

		VMCALL void rv_slliw() {
			UINT8 _rd = 0, _rs1 = 0; INT32 v1 = 0; UINT32 _shamt = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);
			ScrRead (UINT32, _shamt, imm);

			RegRead (INT32, v1, _rs1);

			if ((_shamt >> 5) != 0) {
				CSR_SET_TRAP (Vmcs->Gpr->Pc, illegal_instruction, 0, (UINT64)Vmcs->Gpr->Scratch, 1);
			}

			RegWrite (INT32, _rd, v1 << (_shamt & 0x1F));
		}

		VMCALL void rv_srliw() {
			UINT8 _rd = 0, _rs1 = 0; INT32 v1 = 0; UINT32 _shamt = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);
			ScrRead (UINT32, _shamt, imm);

			RegRead (INT32, v1, _rs1);

			if ((_shamt >> 5) != 0) {
				CSR_SET_TRAP (Vmcs->Gpr->Pc, illegal_instruction, 0, (UINT64)Vmcs->Gpr->Scratch, 1);
			}

			RegWrite (INT32, _rd, v1 >> (_shamt & 0x1F));
		}

		VMCALL void rv_sraiw() {
			UINT8 _rd = 0, _rs1 = 0; INT32 v1 = 0; UINT32 _shamt = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);
			ScrRead (UINT32, _shamt, imm);

			RegRead (INT32, v1, _rs1);

			if ((_shamt >> 5) != 0) {
				CSR_SET_TRAP (Vmcs->Gpr->Pc, illegal_instruction, 0, (UINT64)Vmcs->Gpr->Scratch, 1);
			}
			// TODO: this may be wrong to mask
			RegWrite (INT32, _rd, v1 >> (_shamt & 0x1F));
		}

		VMCALL void rv_lb() {
			UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; UINT_PTR address = 0; INT8 v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);
			ScrRead (INT32, _imm, imm);

			RegRead (UINT_PTR, address, _rs1);
			address += (INT_PTR)_imm;

			MemRead (INT8, v1, address);
			RegWrite (INT8, _rd, v1);
		}

		VMCALL void rv_lh() {
			UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; UINT_PTR address = 0; INT16 v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);
			ScrRead (INT32, _imm, imm);

			RegRead (UINT_PTR, address, _rs1);
			address += (INT_PTR)_imm;

			MemRead (INT16, v1, address);
			RegWrite (INT16, _rd, v1);
		}

		VMCALL void rv_lw() {
			UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; UINT_PTR address = 0; INT32 v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);
			ScrRead (INT32, _imm, imm);

			RegRead (UINT_PTR, address, _rs1);
			address += (INT_PTR)_imm;

			MemRead (INT32, v1, address);
			RegWrite (INT32, _rd, v1);
		}

		VMCALL void rv_lbu() {
			UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; UINT_PTR address = 0; UINT8 v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);
			ScrRead (INT32, _imm, imm);

			RegRead (UINT_PTR, address, _rs1);
			address += (INT_PTR)_imm;

			MemRead (UINT8, v1, address);
			RegWrite (UINT8, _rd, v1);
		}

		VMCALL void rv_lhu() {
			UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; UINT_PTR address = 0; UINT16 v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);
			ScrRead (INT32, _imm, imm);

			RegRead (UINT_PTR, address, _rs1);
			address += (INT_PTR)_imm;

			MemRead (UINT16, v1, address);
			RegWrite (UINT16, _rd, v1);
		}

		VMCALL void rv_lwu() {
			UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; UINT_PTR address = 0; UINT32 v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);
			ScrRead (INT32, _imm, imm);

			RegRead (UINT_PTR, address, _rs1);
			address += (INT_PTR)_imm;

			MemRead (UINT32, v1, address);
			RegWrite (UINT32, _rd, v1);
		}

		VMCALL void rv_ld() {
			UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; UINT_PTR address = 0; INT64 v1 = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);
			ScrRead (INT32, _imm, imm);

			RegRead (UINT_PTR, address, _rs1);
			address += (INT_PTR)_imm;

			MemRead (INT64, v1, address);
			RegWrite (INT64, _rd, v1);
		}

		VMCALL void rv_jalr() {
			UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; UINT_PTR address = 0;

			ScrRead (UINT8, _rd, rd);
			ScrRead (UINT8, _rs1, rs1);
			ScrRead (INT32, _imm, imm);

			RegRead (UINT_PTR, address, _rs1);
			address += (INT_PTR)_imm;
			address &= ~((INT_PTR)1);

			RegWrite (UINT_PTR, _rd, Vmcs->Gpr->Pc);
			Vmcs->Gpr->Pc = address;

			if (auto HostMem = MemoryCheck (Vmcs->Gpr->Pc)) {
				Vmcs->Gpr->Pc = (UINT_PTR)HostMem;
				CSR_SET_TRAP (Vmcs->Gpr->Pc, environment_execute, 0, 0, 0);
			}
			if (!PROCESS_MEMORY_IN_BOUNDS(Vmcs->Gpr->Pc)) {
				CSR_SET_TRAP (Vmcs->Gpr->Pc, environment_call_native, 0, 0, 0);
			}
		}

		VMCALL void rv_flq() {
			CSR_SET_TRAP (Vmcs->Gpr->Pc, illegal_instruction, 0, 0, 1);
		}

		VMCALL void rv_fence() {
			CSR_SET_TRAP (Vmcs->Gpr->Pc, illegal_instruction, 0, 0, 1);
		}

		VMCALL void rv_fence_i() {
			CSR_SET_TRAP (Vmcs->Gpr->Pc, illegal_instruction, 0, 0, 1);
		}

		VMCALL void rv_ecall() {
			/*
			   Description
			   Make a request to the supporting execution environment.
			   When executed in U-mode, S-mode, or M-mode, it generates an environment-call-from-U-mode exception,
			   environment-call-from-S-mode exception, or environment-call-from-M-mode exception, respectively, and performs no other operation.

			   Implementation
			   RaiseException(EnvironmentCall)

			   */
			CSR_SET_TRAP (Vmcs->Gpr->Pc, illegal_instruction, 0, 0, 1);
		}

		VMCALL void rv_ebreak() {
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
		VMCALL void rv_csrrw() {
			/*
			   Description
			   Atomically swaps values in the CSRs and integer registers.
			   CSRRW reads the old value of the CSR, zero-extends the value to XLEN bits, then writes it to integer register _rd.
			   The initial value in _rs1 is written to the CSR.
			   If _rd=x0, then the instruction shall not read the CSR and shall not cause any of the side effects that might occur on a CSR read.

			   Implementation
			   t = CSRs[csr]; CSRs[csr] = x[_rs1]; x[_rd] = t
			   */
			CSR_SET_TRAP (Vmcs->Gpr->Pc, illegal_instruction, 0, 0, 1);
		}

		VMCALL void rv_csrrs() {
			/*
			   Description
			   Reads the value of the CSR, zero-extends the value to XLEN bits, and writes it to integer register _rd.
			   The initial value in integer register _rs1 is treated as a bit mask that specifies bit positions to be set in the CSR.
			   Any bit that is high in _rs1 will cause the corresponding bit to be set in the CSR, if that CSR bit is writable.
			   Other bits in the CSR are unaffected (though CSRs might have side effects when written).

			   Implementation
			   t = CSRs[csr]; CSRs[csr] = t | x[_rs1]; x[_rd] = t
			   */
			CSR_SET_TRAP (Vmcs->Gpr->Pc, illegal_instruction, 0, 0, 1);
		}

		VMCALL void rv_csrrc() {
			/*
			   Description
			   Reads the value of the CSR, zero-extends the value to XLEN bits, and writes it to integer register _rd.
			   The initial value in integer register _rs1 is treated as a bit mask that specifies bit positions to be cleared in the CSR.
			   Any bit that is high in _rs1 will cause the corresponding bit to be cleared in the CSR, if that CSR bit is writable.
			   Other bits in the CSR are unaffected.

			   Implementation
			   t = CSRs[csr]; CSRs[csr] = t &~x[_rs1]; x[_rd] = t
			   */
			CSR_SET_TRAP (Vmcs->Gpr->Pc, illegal_instruction, 0, 0, 1);
		}

		VMCALL void rv_csrrwi() {
			/*
			   Description
			   Update the CSR using an XLEN-bit value obtained by zero-extending a 5-bit unsigned immediate (uimm[4:0]) field encoded in the _rs1 field.

			   Implementation
			   x[_rd] = CSRs[csr]; CSRs[csr] = zimm
			   */
			CSR_SET_TRAP (Vmcs->Gpr->Pc, illegal_instruction, 0, 0, 1);
		}

		VMCALL void rv_csrrsi() {
			/*
			   Description
			   Set CSR bit using an XLEN-bit value obtained by zero-extending a 5-bit unsigned immediate (uimm[4:0]) field encoded in the _rs1 field.

			   Implementation
			   t = CSRs[csr]; CSRs[csr] = t | zimm; x[_rd] = t
			   */
			CSR_SET_TRAP (Vmcs->Gpr->Pc, illegal_instruction, 0, 0, 1);
		}

		VMCALL void rv_csrrci() {
			/*
			   Description
			   Clear CSR bit using an XLEN-bit value obtained by zero-extending a 5-bit unsigned immediate (uimm[4:0]) field encoded in the _rs1 field.

			   Implementation
			   t = CSRs[csr]; CSRs[csr] = t &~zimm; x[_rd] = t
			   */
			CSR_SET_TRAP (Vmcs->Gpr->Pc, illegal_instruction, 0, 0, 1);
		}
	}

namespace rtype {
	VMCALL void rv_scw() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT32 value = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		MemRead (UINT_PTR, address, _rs1);
		RegRead (INT32, value, _rs2);

		if (rvm64::memory::vm_check_load_rsv(0, address)) {
			rvm64::memory::vm_set_load_rsv(0, address);

			MemWrite (INT32, address, value);
			RegWrite (INT32, _rd, 0);

			rvm64::memory::vm_clear_load_rsv(0);
		} else {
			RegWrite (INT32, _rd, 1);
		}
	}

	VMCALL void rv_scd() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT64 value = 0; UINT_PTR address = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (INT64, value, _rs2);

		if (!rvm64::memory::vm_check_load_rsv(0, address)) {
			rvm64::memory::vm_set_load_rsv(0, address);

			MemWrite (INT64, address, value);
			RegWrite (INT64, _rd, 0);

			rvm64::memory::vm_clear_load_rsv(0);

		} else {
			RegWrite (INT64, _rd, 1);
		}
	}

	VMCALL void rv_fadd_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; float v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (float, v1, _rs1);
		RegRead (float, v2, _rs2);

		RegWrite (float, _rd, (v1 + v2));
	}

	VMCALL void rv_fsub_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; float v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (float, v1, _rs1);
		RegRead (float, v2, _rs2);

		RegWrite (float, _rd, (v1 - v2));
	}

	VMCALL void rv_fmul_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; float v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (float, v1, _rs1);
		RegRead (float, v2, _rs2);

		RegWrite (float, _rd, (v1 * v2));
	}

	VMCALL void rv_fdiv_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; float v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (float, v1, _rs1);
		RegRead (float, v2, _rs2);

		RegWrite (float, _rd, (v1 / v2));
	}

	VMCALL void rv_fsgnj_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT64 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT64, v1, _rs1);
		RegRead (INT64, v2, _rs2);

		INT64 s2 = (v2 >> 63) & 1;

		v1 &= ~(1LL << 63);
		v1 |= (s2 << 63);

		RegWrite (INT64, _rd, v1);
	}

	VMCALL void rv_fsgnjn_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT64 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT64, v1, _rs1);
		RegRead (INT64, v2, _rs2);

		INT64 s2 = ((v2 >> 63) & 1) ^ 1;

		v1 &= ~(1LL << 63);
		v1 |= (s2 << 63);

		RegWrite (INT64, _rd, v1);
	}

	VMCALL void rv_fsgnjx_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT64 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT64, v1, _rs1);
		RegRead (INT64, v2, _rs2);

		INT64 s1 = (v1 >> 63) & 1;
		INT64 s2 = (v2 >> 63) & 1;

		v1 &= ~(1LL << 63);
		v1 |= ((s1 ^ s2) << 63);

		RegWrite (INT64, _rd, v1);
	}

	VMCALL void rv_fmin_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; double v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (double, v1, _rs1);
		RegRead (double, v2, _rs2);

		if (is_nan(v1)) {
			RegWrite (double, _rd, v2);
		} else if (is_nan(v2)) {
			RegWrite (double, _rd, v1);
		} else {
			RegWrite (double, _rd, (v1 > v2) ? v2 : v1);
		}
	}

	VMCALL void rv_fmax_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; double v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (double, v1, _rs1);
		RegRead (double, v2, _rs2);

		if (is_nan(v1)) {
			RegWrite (double, _rd, v2);
		} else if (is_nan(v2)) {
			RegWrite (double, _rd, v1);
		} else {
			RegWrite (double, _rd, (v1 > v2) ? v1 : v2);
		}
	}

	VMCALL void rv_feq_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; double v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (double, v1, _rs1);
		RegRead (double, v2, _rs2);

		if (is_nan(v1) || is_nan(v2)) {
			RegWrite (bool, _rd, false);
			return;
		}

		RegWrite (bool, _rd, (v1 == v2));
	}

	VMCALL void rv_flt_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; double v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (double, v1, _rs1);
		RegRead (double, v2, _rs2);

		if (is_nan(v1) || is_nan(v2)) {
			RegWrite (bool, _rd, false);
			return;
		}

		RegWrite (bool, _rd, (v1 < v2));
	}

	VMCALL void rv_fle_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; double v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (double, v1, _rs1);
		RegRead (double, v2, _rs2);

		if (is_nan(v1) || is_nan(v2)) {
			RegWrite (bool, _rd, false);
			return;
		}

		RegWrite (bool, _rd, (v1 <= v2));
	}

	VMCALL void rv_addw() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT32, v1, _rs1);
		RegRead (INT32, v2, _rs2);

		RegWrite (INT64, _rd, (INT64)(v1 + v2));
	}

	VMCALL void rv_subw() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT32, v1, _rs1);
		RegRead (INT32, v2, _rs2);

		RegWrite (INT64, _rd, (INT64)(v1 - v2));
	}

	VMCALL void rv_mulw() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT32, v1, _rs1);
		RegRead (INT32, v2, _rs2);

		RegWrite (INT64, _rd, (INT64)(v1 * v2));
	}

	VMCALL void rv_srlw() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0; UINT32 v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT32, v1, _rs1);
		RegRead (UINT32, v2, _rs2);

		RegWrite (INT32, _rd, (v1 >> (v2 & 0x1F)));
	}

	VMCALL void rv_sraw() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0; UINT32 v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT32, v1, _rs1);
		RegRead (UINT32, v2, _rs2);

		RegWrite (INT32, _rd, (v1 >> (v2 & 0x1F)));
	}

	VMCALL void rv_divuw() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT32 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT32, v1, _rs1);
		RegRead (UINT32, v2, _rs2);

		RegWrite (UINT32, _rd, (v1 / v2));
	}

	VMCALL void rv_sllw() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0; UINT32 v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT32, v1, _rs1);
		RegRead (INT32, v2, _rs2);

		RegWrite (INT32, _rd, (v1 << (v2 & 0x1F)));
	}

	VMCALL void rv_divw() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT32, v1, _rs1);
		RegRead (INT32, v2, _rs2);

		RegWrite (INT32, _rd, (v1 / v2));
	}

	VMCALL void rv_remw() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT32, v1, _rs1);
		RegRead (INT32, v2, _rs2);

		RegWrite (INT32, _rd, (v1 % v2));
	}

	VMCALL void rv_remuw() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT32 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT32, v1, _rs1);
		RegRead (UINT32, v2, _rs2);

		RegWrite (UINT32, _rd, (v1 % v2));
	}

	VMCALL void rv_add() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT32, v1, _rs1);
		RegRead (INT32, v2, _rs2);

		RegWrite (INT32, _rd, (v1 + v2));
	}

	VMCALL void rv_sub() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT32, v1, _rs1);
		RegRead (INT32, v2, _rs2);

		RegWrite (INT32, _rd, (v1 - v2));
	}

	VMCALL void rv_mul() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT32, v1, _rs1);
		RegRead (INT32, v2, _rs2);

		RegWrite (INT32, _rd, (v1 * v2));
	}

	VMCALL void rv_sll() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0; UINT32 v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT32, _rs1, v1);
		RegRead (INT32, _rs2, v2);

		RegWrite (INT32, _rd, (v1 << (v2 & 0x1F)));
	}

	VMCALL void rv_mulh() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT_PTR v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT_PTR, v1, _rs1);
		RegRead (INT_PTR, v2, _rs2);

#if UINTPTR_MAX == 0xFFFFFFFF
		INT64 result = (INT64)v1 * (INT64)v2;
		RegWrite (INT32, _rd, (result >> 32));

#elif UINTPTR_MAX == 0xFFFFFFFFFFFFFFFF
		__int128 result = (__int128)v1 * (__int128)v2;
		RegWrite (INT64, _rd, (result >> 64));

#endif
	}

	VMCALL void rv_slt() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT_PTR v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT_PTR, v1, _rs1);
		RegRead (INT_PTR, v2, _rs2);

		RegWrite (INT_PTR, _rd, ((v1 < v2) ? 1 : 0));
	}

	VMCALL void rv_mulhsu() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT_PTR v1 = 0; UINT_PTR v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT_PTR, v1, _rs1);
		RegRead (UINT_PTR, v2, _rs2);

#if UINTPTR_MAX == 0xFFFFFFFF
		INT64 result = (INT64)(INT32)v1 * (UINT64)(UINT32)v2;
		RegWrite (INT32, _rd, (result >> 32));

#elif UINTPTR_MAX == 0xFFFFFFFFFFFFFFFF
		__int128 result = (__int128) (INT64) v1 * (__uint128_t) (UINT64) v2;
		RegWrite (INT64, _rd, (result >> 64));
#endif
	}

	VMCALL void rv_sltu() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, v1, _rs1);
		RegRead (UINT_PTR, v2, _rs2);

		RegWrite (UINT_PTR, _rd, ((v1 < v2) ? 1 : 0));
	}

	VMCALL void rv_mulhu() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, v1, _rs1);
		RegRead (UINT_PTR, v2, _rs2);

		UINT_PTR result = v1 * v2;

#if UINTPTR_MAX == 0xFFFFFFFF
		RegWrite (UINT_PTR, _rd, (result >> 16));
#elif UINTPTR_MAX == 0xFFFFFFFFFFFFFFFF
		RegWrite (UINT_PTR, _rd, (result >> 32));
#endif
	}

	VMCALL void rv_xor() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, v1, _rs1);
		RegRead (UINT_PTR, v2, _rs2);

		RegWrite (UINT_PTR, _rd, (v1 ^ v2));
	}

	VMCALL void rv_div() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, v1, _rs1);
		RegRead (UINT_PTR, v2, _rs2);

		RegWrite (UINT_PTR, _rd, (v1 / v2));
	}

	VMCALL void rv_srl() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR v1 = 0; UINT32 v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, v1, _rs1);
		RegRead (UINT32, v2, _rs2);

		RegWrite (UINT_PTR, _rd, (v1 >> (v2 & 0x1F)));
	}

	VMCALL void rv_sra() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT_PTR v1 = 0; UINT32 v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT_PTR, v1, _rs1);
		RegRead (UINT32, v2, _rs2);

		RegWrite (INT_PTR, _rd, (v1 >> (v2 & 0x1F)));
	}

	VMCALL void rv_divu() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, v1, _rs1);
		RegRead (UINT_PTR, v2, _rs2);

		if (v2 == 0) {
			RegWrite (UINT_PTR, _rd, 0);
		} else {
			RegWrite (UINT_PTR, _rd, (v1 / v2));
		}
	}

	VMCALL void rv_or() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT_PTR v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT_PTR, _rs1, v1);
		RegRead (INT_PTR, _rs2, v2);

		RegWrite (INT_PTR, _rd, (v1 | v2));
	}

	VMCALL void rv_rem() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT_PTR v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (INT_PTR, v1, _rs1);
		RegRead (INT_PTR, v2, _rs2);

		if (v2 == 0) {
			RegWrite (INT_PTR, _rd, 0);
		} else {
			RegWrite (INT_PTR, _rd, (v1 % v2));
		}
	}

	VMCALL void rv_and() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, v1, _rs1);
		RegRead (UINT_PTR, v2, _rs2);

		RegWrite (UINT_PTR, _rd, (v1 & v2));
	}

	VMCALL void rv_remu() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, v1, _rs1);
		RegRead (UINT_PTR, v2, _rs2);

		if (v2 == 0) {
			RegWrite (UINT_PTR, _rd, 0);
		} else {
			RegWrite (UINT_PTR, _rd, (v1 % v2));
		}
	}

	VMCALL void rv_amoswap_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT64 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (INT64, v2, _rs2);

		MemRead (INT64, v1, address);
		MemWrite (INT64, address, v2);
		RegWrite (INT64, _rd, v1);

	}

	VMCALL void rv_amoadd_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT64 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (INT64, v2, _rs2);


		MemRead (INT64, v1, address);
		MemWrite (INT64, address, (v1 + v2));
		RegWrite (INT64, _rd, v1);

	}

	VMCALL void rv_amoxor_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT64 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (INT64, v2, _rs2);


		MemRead (INT64, v1, address);
		MemWrite (INT64, address, (v1 ^ v2));
		RegWrite (INT64, _rd, v1);

	}

	VMCALL void rv_amoand_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT64 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (INT64, v2, _rs2);


		MemRead (INT64, v1, address);
		MemWrite (INT64, address, (v1 & v2));
		RegWrite (INT64, _rd, v1);

	}

	VMCALL void rv_amoor_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT64 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (INT64, v2, _rs2);


		MemRead (INT64, v1, address);
		MemWrite (INT64, address, (v1 | v2));
		RegWrite (INT64, _rd, v1);

	}

	VMCALL void rv_amomin_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT64 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (UINT64, v2, _rs2);


		MemRead (INT64, v1, address);
		MemWrite (INT64, address, (v1 < v2 ? v1 : v2));
		RegWrite (UINT64, _rd, v1);

	}

	VMCALL void rv_amomax_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT64 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (INT64, v2, _rs2);


		MemRead (INT64, v1, address);
		MemWrite (INT64, address, (v1 < v2 ? v2 : v1));
		RegWrite (INT64, _rd, v1);

	}

	VMCALL void rv_amominu_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; UINT64 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, _rs1, address);
		RegRead (UINT64, _rs2, v2);


		MemRead (UINT64, v1, address);
		MemWrite (UINT64, address, (v1 < v2 ? v1 : v2));
		RegWrite (UINT64, _rd, v1);

	}

	VMCALL void rv_amomaxu_d() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; UINT64 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (UINT64, v2, _rs2);

		MemRead (UINT64, v1, address);

		MemWrite (UINT64, address, (v1 < v2 ? v2 : v1));
		RegWrite (UINT64, _rd, v1);
	}

	VMCALL void rv_amoswap_w() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT32 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (INT32, v2, _rs2);

		MemRead (INT32, v1, address);

		MemWrite (INT32, address, v2);
		RegWrite (INT32, _rd, v1);
	}

	VMCALL void rv_amoadd_w() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT32 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (INT32, v2, _rs2);

		MemRead (INT32, v1, address);
		MemWrite (INT32, address, (v1 + v2));

		RegWrite (INT32, _rd, v1);
	}

	VMCALL void rv_amoxor_w() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT32 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (INT32, v2, _rs2);

		MemRead (INT32, v1, address);
		MemWrite (INT32, address, (v1 ^ v2));

		RegWrite (INT32, _rd, v1);
	}

	VMCALL void rv_amoand_w() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT32 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (INT32, v2, _rs2);


		MemRead (INT32, v1, address);
		MemWrite (INT32, address, (v1 & v2));
		RegWrite (INT32, _rd, v1);

	}

	VMCALL void rv_amoor_w() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT32 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (INT32, v2, _rs2);


		MemRead (INT32, v1, address);
		MemWrite (INT32, address, (v1 | v2));
		RegWrite (INT32, _rd, v1);

	}

	VMCALL void rv_amomin_w() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT32 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (INT32, v2, _rs2);


		MemRead (INT32, v1, address);
		MemWrite (INT32, address, (v1 < v2 ? v1 : v2));
		RegWrite (INT32, _rd, v1);

	}

	VMCALL void rv_amomax_w() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT32 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (INT32, v2, _rs2);


		MemRead (INT32, v1, address);
		MemWrite (INT32, address, (v1 < v2 ? v2 : v1));
		RegWrite (INT32, _rd, v1);

	}

	VMCALL void rv_amominu_w() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; UINT32 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (UINT32, v2, _rs2);


		MemRead (UINT32, v1, address);
		MemWrite (UINT32, address, (v1 < v2 ? v1 : v2));
		RegWrite (UINT32, _rd, v1);

	}

	VMCALL void rv_amomaxu_w() {
		UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; UINT32 v1 = 0, v2 = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (UINT32, v2, _rs2);


		MemRead (UINT32, v1, address);
		MemWrite (UINT32, address, (v1 < v2 ? v2 : v1));
		RegWrite (UINT32, _rd, v1);

	}
};

namespace utype {
	VMCALL void rv_lui() {
		UINT8 _rd = 0; INT32 _imm = 0;

		ScrRead (UINT32, _rd, rd);
		ScrRead (INT32, _imm, imm);
		RegWrite (INT32, _rd, _imm);
	}

	VMCALL void rv_auipc() {
		UINT8 _rd = 0; INT32 _imm = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (INT32, _imm, imm);
		RegWrite (INT64, _rd, (INT64)Vmcs->Gpr->Pc + _imm);
	}
}

namespace jtype {
	VMCALL void rv_jal() {
		UINT8 _rd = 0; INT_PTR offset = 0;

		ScrRead (UINT8, _rd, rd);
		ScrRead (INT_PTR, offset, imm);
		RegWrite (UINT_PTR, _rd, Vmcs->Gpr->Pc + 4);

		Vmcs->Gpr->Pc += offset;
		CSR_SET_TRAP (nullptr, environment_branch, 0, 0, 0);
	}
}

namespace btype {
	VMCALL void rv_beq() {
		UINT8 _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0; INT_PTR offset = 0;

		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);
		ScrRead (INT_PTR, offset, imm);

		RegRead (INT32, v1, _rs1);
		RegRead (INT32, v2, _rs2);

		if (v1 == v2) {
			Vmcs->Gpr->Pc += offset;
			CSR_SET_TRAP (nullptr, environment_branch, 0, 0, 0);
		}
	}

	VMCALL void rv_bne() {
		UINT8 _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0; INT_PTR offset = 0;

		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);
		ScrRead (INT_PTR, offset, imm);

		RegRead (INT32, v1, _rs1);
		RegRead (INT32, v2, _rs2);

		if (v1 != v2) {
			Vmcs->Gpr->Pc += offset;
			CSR_SET_TRAP (nullptr, environment_branch, 0, 0, 0);
		}
	}

	VMCALL void rv_blt() {
		UINT8 _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0; INT_PTR offset = 0;

		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);
		ScrRead (INT_PTR, offset, imm);

		RegRead (INT32, v1, _rs1);
		RegRead (INT32, v2, _rs2);

		if (v1 < v2) {
			Vmcs->Gpr->Pc += offset;
			CSR_SET_TRAP (nullptr, environment_branch, 0, 0, 0);
		}
	}

	VMCALL void rv_bge() {
		UINT8 _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0; INT_PTR offset = 0;

		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);
		ScrRead (INT_PTR, offset, imm);

		RegRead (INT32, v1, _rs1);
		RegRead (INT32, v2, _rs2);

		if (v1 >= v2) {
			Vmcs->Gpr->Pc += offset;
			CSR_SET_TRAP (nullptr, environment_branch, 0, 0, 0);
		}
	}

	VMCALL void rv_bltu() {
		UINT8 _rs1 = 0, _rs2 = 0; UINT32 v1 = 0, v2 = 0; INT_PTR offset = 0;

		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);
		ScrRead (INT_PTR, offset, imm);

		RegRead (UINT32, v1, _rs1);
		RegRead (UINT32, v2, _rs2);

		if (v1 < v2) {
			Vmcs->Gpr->Pc += offset;
			CSR_SET_TRAP (nullptr, environment_branch, 0, 0, 0);
		}
	}

	VMCALL void rv_bgeu() {
		UINT8 _rs1 = 0, _rs2 = 0; UINT32 v1 = 0, v2 = 0; INT_PTR offset = 0;

		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);
		ScrRead (INT_PTR, offset, imm);

		RegRead (UINT32, v1, _rs1);
		RegRead (UINT32, v2, _rs2);

		if (v1 >= v2) {
			Vmcs->Gpr->Pc += offset;
			CSR_SET_TRAP (nullptr, environment_branch, 0, 0, 0);
		}
	}
}

namespace stype {
	VMCALL void rv_sb() {
		UINT8 _rs1 = 0, _rs2 = 0; INT32 _imm = 0; UINT_PTR address = 0; UINT8 v1 = 0;

		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);
		ScrRead (INT32, _imm, imm);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (INT8, v1, _rs2);

		address += (INT_PTR)_imm;
		MemWrite (UINT8, address, v1);
	}

	VMCALL void rv_sh() {
		UINT8 _rs1 = 0, _rs2 = 0; INT32 _imm = 0; UINT_PTR address = 0; UINT16 v1 = 0;

		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);
		ScrRead (INT32, _imm, imm);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (UINT16, v1, _rs2);

		address += (INT_PTR)_imm;
		MemWrite (UINT16, address, v1);
	}

	VMCALL void rv_sw() {
		UINT8 _rs1 = 0, _rs2 = 0; INT32 _imm = 0; UINT_PTR address = 0; UINT32 v1 = 0;

		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);
		ScrRead (INT32, _imm, imm);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (UINT32, v1, _rs2);

		address += (INT_PTR)_imm;
		MemWrite (UINT32, address, v1);
	}

	VMCALL void rv_sd() {
		UINT8 _rs1 = 0, _rs2 = 0; INT32 _imm = 0; UINT_PTR address = 0; UINT64 v1 = 0;

		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);
		ScrRead (INT32, _imm, imm);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (UINT64, v1, _rs2);

		address += (INT_PTR)_imm;
		MemWrite (UINT64, address, v1);
	}

	VMCALL void rv_fsw() {
		UINT8 _rs1 = 0, _rs2 = 0; INT32 _imm = 0; UINT_PTR address = 0; float v1 = 0;

		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);
		ScrRead (INT32, _imm, imm);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (float, v1, _rs2);

		address += (INT_PTR)_imm;
		MemWrite (float, address, v1);
	}

	VMCALL void rv_fsd() {
		UINT8 _rs1 = 0, _rs2 = 0; INT32 _imm = 0; UINT_PTR address = 0; double v1 = 0;

		ScrRead (UINT8, _rs1, rs1);
		ScrRead (UINT8, _rs2, rs2);
		ScrRead (INT32, _imm, imm);

		RegRead (UINT_PTR, address, _rs1);
		RegRead (UINT64, v1, _rs2);

		address += (INT_PTR)_imm;
		MemWrite (double, address, v1);
	}
}

namespace r4type {

};

VM_DATA const UINT_PTR DispatchTable [256] = {
#define ENCRYPT(op) EncryptPtr ((UINT_PTR)(op), (UINT_PTR)0)

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
#endif // VMCODE_H
