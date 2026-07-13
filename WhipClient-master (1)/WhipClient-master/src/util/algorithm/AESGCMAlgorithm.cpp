

#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../../includes/util/algorithm/AESGCMAlgorithm.h"
#include "util/algorithm/AESEAlgorithm.h"

#define Block 16
#define IVlen 12

static char BIT_helper(unsigned char value) {
    switch (value) {
        case 7: return 0x80; case 6: return 0x40;
        case 5: return 0x20; case 4: return 0x10;
        case 3: return 0x08; case 2: return 0x04;
        case 1: return 0x02; case 0: return 0x01;
        default: return 0x00;
    }
}

static void ShiftRight_helper(unsigned char *SHFT) {
    unsigned char prevcarry = 0x00;
    unsigned char currcarry = 0x00;
    for (int i = 0; i < Block; i++) {
        prevcarry = currcarry;
        currcarry = (SHFT[i] & 0x01) ? 0x80 : 0x00;
        SHFT[i] >>= 1;
        SHFT[i] += prevcarry;
    }
}

static void xor_block_helper(unsigned char *ZBLOCK, unsigned char *VBLOCK) {
    for (int i = 0; i < Block; i++) {
        ZBLOCK[i] = ZBLOCK[i] ^ VBLOCK[i];
    }
}

static void GFMult128_helper(unsigned char *Z, const unsigned char *X, const unsigned char *YBLOCK,
                              unsigned char *V_work, const unsigned char *R_const) {
    memset(Z, 0, Block);
    memcpy(V_work, YBLOCK, Block);

    for (int i = 0; i < Block; i++) {
        for (int j = 0; j < 8; j++) {
            if (X[i] & BIT_helper(7 - j)) {
                xor_block_helper(Z, V_work);
            }
            if (V_work[15] & 0x01) {
                ShiftRight_helper(V_work);
                V_work[0] ^= R_const[0];
            } else {
                ShiftRight_helper(V_work);
            }
        }
    }
}

static void InitialHashSubkey_helper(unsigned char *ENC, const unsigned char *k) {
    memset(ENC, 0, Block);
    aes128e(ENC, ENC, k);
}

static void J0Definition_helper(unsigned char *J0, const unsigned char *IV, unsigned long *increment) {
    memcpy(J0, IV, IVlen);
    *increment = 1;
    J0[Block - 1] = *increment;
}

static void IncrementingFunction_helper(unsigned char *INC, unsigned long *increment) {
    (*increment) += 1;
    for (int i = 0; i < 4; ++i) {
        INC[Block - 1 - i] = ((*increment) >> (8 * i)) & 0xFF;
    }
}

static void GCTR_helper(unsigned char *output, const unsigned char *J0_start, const unsigned char *input,
                        const unsigned char *k, const unsigned long len_blocks,
                        unsigned char *CB_work, unsigned long *increment) {
    unsigned char tempCB[Block] = {0};
    memcpy(CB_work, J0_start, Block);

    for (unsigned long i = 0; i < len_blocks; i++) {
        aes128e(tempCB, CB_work, k);
        for (int j = 0; j < Block; j++) {
            output[(i * Block) + j] = input[(i * Block) + j] ^ tempCB[j];
        }
        IncrementingFunction_helper(CB_work, increment);
    }
}

static void GHASH_helper(unsigned char *OUT, const unsigned char *H, const unsigned char *X,
                         const unsigned int len_total, unsigned char *Z_work, unsigned char *V_work,
                         const unsigned char *R_const) {
    unsigned char Y[Block] = {0};
    unsigned char tempX[Block] = {0};

    for (unsigned int i = 0; i < (len_total / Block); i++) {
        for (int j = 0; j < Block; j++) {
            tempX[j] = X[(i * Block) + j];
        }
        xor_block_helper(Y, tempX);
        GFMult128_helper(Z_work, H, Y, V_work, R_const);
        memcpy(Y, Z_work, Block);
    }
    memcpy(OUT, Y, Block);
}

static void ByteConcatenation_fixed(unsigned char *concat, const unsigned char *A, const unsigned char *C,
                                    unsigned long len_ad_blocks, unsigned long len_c_blocks,
                                    unsigned int len_total) {
    memset(concat, 0, len_total);

    uint64_t len_ad_bits = (uint64_t)len_ad_blocks * Block * 8;
    uint64_t len_c_bits = (uint64_t)len_c_blocks * Block * 8;

    if (len_ad_blocks > 0) {
        memcpy(concat, A, len_ad_blocks * Block);
    }

    if (len_c_blocks > 0) {
        memcpy(concat + (len_ad_blocks * Block), C, len_c_blocks * Block);
    }

    unsigned char len_block[Block];
    memset(len_block, 0, Block);

    for (int i = 0; i < 8; i++) {
        len_block[7 - i] = (len_ad_bits >> (8 * i)) & 0xFF;
    }

    for (int i = 0; i < 8; i++) {
        len_block[15 - i] = (len_c_bits >> (8 * i)) & 0xFF;
    }

    size_t offset = (len_ad_blocks * Block) + (len_c_blocks * Block);
    memcpy(concat + offset, len_block, Block);
}

static unsigned char H_enc[Block] = {0};
static unsigned char J0_enc[Block] = {0};
static unsigned char CB_enc[Block] = {0};
static unsigned char OUTPUT_enc[Block] = {0};
static unsigned char R_enc[Block] = {0xe1};
static unsigned char Z_enc[Block] = {0};
static unsigned char V_enc[Block] = {0};
static unsigned long increment_enc;

void aes128gcm(unsigned char *ciphertext, unsigned char *tag, const unsigned char *k, const unsigned char *IV,
               const unsigned char *plaintext, const unsigned long len_p, const unsigned char *add_data,
               const unsigned long len_ad) {

    unsigned int len_total = (len_p * Block) + (len_ad * Block) + Block;

    unsigned char *concat = (unsigned char *)malloc(len_total);
    if (!concat) {
        memset(tag, 0, Block);
        return;
    }

    InitialHashSubkey_helper(H_enc, k);

    J0Definition_helper(J0_enc, IV, &increment_enc);
    IncrementingFunction_helper(J0_enc, &increment_enc);

    GCTR_helper(ciphertext, J0_enc, plaintext, k, len_p, CB_enc, &increment_enc);

    ByteConcatenation_fixed(concat, add_data, ciphertext, len_ad, len_p, len_total);

    GHASH_helper(OUTPUT_enc, H_enc, concat, len_total, Z_enc, V_enc, R_enc);

    J0Definition_helper(J0_enc, IV, &increment_enc);
    GCTR_helper(tag, J0_enc, OUTPUT_enc, k, 1, CB_enc, &increment_enc);

    free(concat);
}

static unsigned char H_dec[Block] = {0};
static unsigned char J0_dec[Block] = {0};
static unsigned char CB_dec[Block] = {0};
static unsigned char OUTPUT_dec[Block] = {0};
static unsigned char R_dec[Block] = {0xe1};
static unsigned char Z_dec[Block] = {0};
static unsigned char V_dec[Block] = {0};
static unsigned long increment_dec;

int aes128gcm_decrypt(unsigned char *plaintext, const unsigned char *ciphertext, const unsigned char *tag,
                      const unsigned char *k, const unsigned char *IV, const unsigned long len_c,
                      const unsigned char *add_data, const unsigned long len_ad) {

    unsigned int len_total = (len_c * Block) + (len_ad * Block) + Block;

    unsigned char *concat = (unsigned char *)malloc(len_total);
    if (!concat) {
        return -1;
    }

    unsigned char computed_tag[Block] = {0};
    unsigned char temp_output[Block] = {0};

    InitialHashSubkey_helper(H_dec, k);

    J0Definition_helper(J0_dec, IV, &increment_dec);

    ByteConcatenation_fixed(concat, add_data, ciphertext, len_ad, len_c, len_total);

    GHASH_helper(temp_output, H_dec, concat, len_total, Z_dec, V_dec, R_dec);

    GCTR_helper(computed_tag, J0_dec, temp_output, k, 1, CB_dec, &increment_dec);

    unsigned char tag_valid = 0;
    for (int i = 0; i < Block; i++) {
        tag_valid |= (computed_tag[i] ^ tag[i]);
    }

    free(concat);

    if (tag_valid != 0) {
        memset(plaintext, 0, len_c * Block);
        return -1;
    }

    J0Definition_helper(J0_dec, IV, &increment_dec);
    IncrementingFunction_helper(J0_dec, &increment_dec);

    GCTR_helper(plaintext, J0_dec, ciphertext, k, len_c, CB_dec, &increment_dec);

    return 0;
}
