/*
 * SM9Reg_util.h
 *
 *  Created on: Mar 17, 2020
 *      Author: veins
 */

#ifndef SM9REG_UTIL_H_
#define SM9REG_UTIL_H_

#include <stdio.h>
#include <cstdio>
#include <string.h>
#include <string>
#include <stdlib.h>
#include "mygmssl/e_os.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sm9.h>
#include <openssl/rand.h>
#include <openssl/sms4.h>
#include "mygmssl/crypto/sm9/sm9_lcl.h"

#define VEHICLE_INIT "vehicle first on road"
#define SM4_ENC_KEY_SIZE 16
#define HASH_LENGTH 64
#define EC_POINT_HEX_LENGTH 128

struct SM9_VRC_REG_T
{
    const char* id;
    BIGNUM *Ta;
    const char* RLP;
    int flag = 1;
};

struct SM9_RSU_REG_T
{
    BIGNUM *Ta;
    unsigned char *point_rj;
    unsigned char *point_pubs;
    unsigned char* RLP;
    unsigned char enc_buf[2 * EC_POINT_HEX_LENGTH];
    int flag = 1;
};

struct SM9_REG_PARAM_T
{
    unsigned char hid = SM9_HID_SIGN;
    const char *sid = "SM9_SYSTEM_ID";
    const BIGNUM *n = SM9_get0_order();
    const BIGNUM *p = SM9_get0_prime();
    const EVP_MD *md = EVP_sm3();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1);
    unsigned char *Ppubs;
};

char* bytes_to_hex(unsigned char *bytes, int len);
void print_hex(const char* label, unsigned char* h, size_t len);
void print_bn(const char* label, const BIGNUM* bn);
BIGNUM* generate_random_number();
int hex_write(FILE *fp, unsigned char* content, unsigned int len, const char* label);
int bn_write(FILE *fp, const char* label, BIGNUM *n);
const char* Search_Identity(unsigned char* buf, int hlen);
char** get_content_by_line(const char* filename, int len, int len_size, unsigned char *buf);
const char* search_content(char** content, unsigned char* buf, int hlen, int len, int len_size);
int rate_pairing_calculate(struct SM9_REG_PARAM_T PubParams, unsigned char** buf, EC_POINT *P1, BIGNUM *t1, point_t *P2, BIGNUM *t2, BIGNUM *r);
double Calc_Last_Distance(struct SM9_RSU_REG_T rsu_struct);
int Calc_New_RLP(struct SM9_RSU_REG_T rsu_struct, unsigned char** rlp);
int Enc_RLP(unsigned char* new_rlp, BIGNUM* krj, const char* idA, struct SM9_REG_PARAM_T PubParams, unsigned char** cyphertxt, unsigned char **kra);
int Calc_Enc_Key(unsigned char *Prj, struct SM9_REG_PARAM_T PubParams, const char *idA, unsigned char** key);
int Check_Cypher(unsigned char *key_buf, const char *idA, unsigned char *cypher, unsigned char **new_rlp);
int sms4_enc(unsigned char* key, const char* idA, unsigned char* new_rlp, unsigned char **cypher, int plen);
int sms4_dec(unsigned char* key, const char* idA, unsigned char* cypher, unsigned char **plain, int clen);
int Calc_PrivateKey(char **dsa, char **dsra, BIGNUM *krj, BIGNUM *ks, const char *idA, struct SM9_REG_PARAM_T PubParams);
int Enc_KEY(char *private_key, unsigned char **cyphertxt, unsigned char *Kra, const char *idA);
int Dec_Key(struct SM9_RSU_REG_T t, unsigned char *key, const char* idA, char** dsa, char** dsra);

int _sms4_enc(unsigned char* key, const char* idA, unsigned char* plain, unsigned char **cypher, int plen);
#endif /* SM9REG_UTIL_H_ */
