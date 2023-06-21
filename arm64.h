#ifndef arm64_h
#define arm64_h

#include <stdio.h>
#include <stdbool.h>

uint32_t generate_movk(uint8_t x, uint16_t val, uint16_t lsl);
uint32_t generate_br(uint8_t x);
bool decode_adrp(uint32_t inst, uint8_t *rd_out, int32_t *imm_out);
bool decode_ldr_imm(uint32_t inst, uint16_t *imm_out, uint8_t *rn_out, uint8_t *rt_out);
bool decode_adrp_ldr(uint32_t adrp_inst, uint32_t ldr_inst, uint64_t pc, uint64_t *dst_out);

#endif /* arm64_h */
