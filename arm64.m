#include "arm64.h"
#include <stdbool.h>

uint32_t generate_movk(uint8_t x, uint16_t val, uint16_t lsl)
{
	uint32_t base = 0b11110010100000000000000000000000;

	uint32_t hw = 0;
	if (lsl == 16) {
		hw = 0b01 << 21;
	}
	else if (lsl == 32) {
		hw = 0b10 << 21;
	}
	else if (lsl == 48) {
		hw = 0b11 << 21;
	}

	uint32_t imm16 = (uint32_t)val << 5;
	uint32_t rd = x & 0x1F;

	return base | hw | imm16 | rd;
}

uint32_t generate_br(uint8_t x)
{
	uint32_t base = 0b11010110000111110000000000000000;
	uint32_t rn = ((uint32_t)x & 0x1F) << 5;
	return base | rn;
}

bool decode_adrp(uint32_t inst, uint8_t *rd_out, int32_t *imm_out)
{
	if ((inst & 0x9F000000) != 0x90000000) return false;
	
	uint32_t mask_immlo = 0b01100000000000000000000000000000;
	uint32_t mask_immhi = 0b00000000111111111111111111100000;
	uint32_t mask_rd    = 0b00000000000000000000000000011111;
	
	int32_t imm = (((inst & mask_immlo) >> 29) | ((inst & mask_immhi) >> 3)) << 12;
	uint8_t rd = inst & mask_rd;
	
	if (rd_out) *rd_out = rd;
	if (imm_out) *imm_out = imm;
	
	return true;
}

bool decode_ldr_imm(uint32_t inst, uint16_t *imm_out, uint8_t *rn_out, uint8_t *rt_out)
{
	if ((inst & 0xBFC00000) != 0xB9400000) return false;
	// TODO: Support non unsigned instructions
	
	uint32_t mask_imm12 = 0b00000000001111111111110000000000;
	uint32_t mask_rn    = 0b00000000000000000000001111100000;
	uint32_t mask_rt    = 0b00000000000000000000000000011111;
	
	uint8_t  rt    = (inst & mask_rt);
	uint8_t  rn    = (inst & mask_rn) >> 5;
	uint16_t imm12 = (inst & mask_imm12) >> 10;
	
	uint32_t bit_is_64_bit = 0b01000000000000000000000000000000;
	if (inst & bit_is_64_bit) {
		imm12 *= 8;
	}
	else {
		imm12 *= 4;
	}
	
	if (imm_out) *imm_out = imm12;
	if (rn_out) *rn_out = rn;
	if (rt_out) *rt_out = rt;
	
	return true;
}

bool decode_adrp_ldr(uint32_t adrp_inst, uint32_t ldr_inst, uint64_t pc, uint64_t *dst_out)
{
	int32_t adrp_imm = 0;
	if (!decode_adrp(adrp_inst, NULL, &adrp_imm)) return false;
	
	uint16_t ldr_imm = 0;
	if (!decode_ldr_imm(ldr_inst, &ldr_imm, NULL, NULL)) return false;
	
	uint64_t pc_page = pc - (pc % 0x1000);
	uint64_t dst = (pc_page + adrp_imm) + ldr_imm;
	if (dst_out) *dst_out = dst;
	return true;
}

/*bool decode_ldr(uint32_t inst, uint8_t *rt_out, uint8_t *rn_out, uint8_t *rm_out)
{
	if ((inst & 0xFFE00C00) != 0xF8600800) return false;
	
	uint32_t mask_rm     = 0b00000000000111110000000000000000;
	uint32_t mask_option = 0b00000000000000001110000000000000;
	uint32_t mask_s      = 0b00000000000000000001000000000000;
	uint32_t mask_rn     = 0b00000000000000000000001111100000;
	uint32_t mask_rt     = 0b00000000000000000000000000011111;
	
	uint8_t rt     = inst & mask_rt;
	uint8_t rn     = inst & mask_rn >> 5;
	uint8_t rm     = inst & mask_rm >> 16;
	bool    s      = inst & mask_s >> 12;
	uint8_t option = inst & mask_option >> 13;
	
	printf("rt=%d, rn=%d, rm=%d, s=%d, option=%X\n", rt, rn, rm, s, option);
	
	return true;
}*/
