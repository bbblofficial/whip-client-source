

#ifndef AES128GCM_H
#define AES128GCM_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "AESEAlgorithm.h"

#ifdef __cplusplus
extern "C" {
#endif

    void aes128gcm(unsigned char *ciphertext, unsigned char *tag, const unsigned char *k, const unsigned char *IV,
                   const unsigned char *plaintext, const unsigned long len_p, const unsigned char *add_data,
                   const unsigned long len_ad);

    int aes128gcm_decrypt(unsigned char *plaintext, const unsigned char *ciphertext, const unsigned char *tag,
                      const unsigned char *k, const unsigned char *IV, const unsigned long len_c,
                      const unsigned char *add_data, const unsigned long len_ad);

#ifdef __cplusplus
}
#endif

#endif
