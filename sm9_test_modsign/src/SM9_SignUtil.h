/*
 * SM9_SignUtil.h
 *
 *  Created on: Mar 30, 2020
 *      Author: veins
 */

#ifndef SM9_SIGNUTIL_H_
#define SM9_SIGNUTIL_H_

#include <stdio.h>
#include <string.h>
#include <string>
#include <stdlib.h>
#include "mygmssl/e_os.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sm9.h>
#include <openssl/rand.h>
#include "mygmssl/crypto/sm9/sm9_lcl.h"

#define MAX_LENGTH 100
#define HASH_LENGTH 64
#define POINT_T_SIZE 384
#define SM4_ENC_KEY_SIZE 16
#define HASH_LENGTH 64
#define EC_POINT_HEX_LENGTH 130

struct SM9_MOD_SIG_T
{
    char *h;
    char *S1;
    char *S2;
    unsigned char *P3_hex;
    unsigned char *Prj_hex;
    unsigned char *Ppubs_hex;
};


struct SM9_SIG_WRAP_T
{
    struct SM9_MOD_SIG_T SM9Signature;
    BIGNUM *TA;
    const char *msg;
};

struct SM9_SIG_PARAM_T
{
    char *dsa;
    char *dsra;
    unsigned char *Pubs_hex;
    unsigned char *Prj_hex;
};

struct SM9_PUB_PARAM_T
{
    unsigned char hid = SM9_HID_SIGN;
    const char *sid = "SM9_SYSTEM_ID";
    const BIGNUM *n = SM9_get0_order();
    const BIGNUM *p = SM9_get0_prime();
    const EVP_MD *md = EVP_sm3();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1);
};


void print_hex(const char* label, unsigned char* h, size_t len);
void print_bn(const char* label, const BIGNUM* bn);
BIGNUM* generate_random_number();
//int read_sign_params(const char *filename, struct SM9_SIG_PARAM_T *params);
char* get_filename(const char *id);
int read_sign_params(char *filename, struct SM9_SIG_PARAM_T *params);
int SM9_hash2(const EVP_MD *md, BIGNUM **h, const char *msg, int msglen, unsigned char *buf0, const BIGNUM *n, BN_CTX *ctx);




#endif /* SM9_SIGNUTIL_H_ */
