/*
 * kap_util.h
 *
 *  Created on: Dec 30, 2019
 *      Author: veins
 */

#ifndef KAP_UTIL_H_
#define KAP_UTIL_H_


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
# include <openssl/bn.h>
# include <openssl/bio.h>
# include <openssl/ec.h>
# include <openssl/evp.h>
#include <errno.h>
#include <openssl/ecdsa.h>
# include <openssl/rand.h>
# include <openssl/engine.h>
# include <openssl/sm2.h>
#include <openssl/pem.h>
#include <openssl/objects.h>
#include <crypto/sm2/sm2_lcl.h>


struct user_t
{
    EC_KEY *user_key;
    SM2_KAP_CTX *ctx;
    const char *id;
    unsigned char *R;
    size_t rlen;
    unsigned char *SharedKey;
    size_t sharedkeyLen;
};

EC_KEY* read_key(char const* key_file);
void shared_key_write(unsigned char *key, int key_len, char *file_name);
FILE *sm2kap_open_file(char const* name, const char *mode);
EC_KEY *sm2kap_read_key(FILE *file);
int fbytes(unsigned char *buf, int num);
int change_rand(const char *hex);
int restore_rand(void);
void print_hex(unsigned char* t, size_t len);
void print_bignum(char flag, const BIGNUM* n);
char* get_id(char const* idfile);
EC_GROUP *new_ec_group(int is_prime_field,
    const char *p_hex, const char *a_hex, const char *b_hex,
    const char *x_hex, const char *y_hex, const char *n_hex, const char *h_hex);
EC_KEY *new_ec_key(const EC_GROUP *group,
    const char *sk, const char *xP, const char *yP);
EC_KEY* test_key(int peer, int type);

#endif /* KAP_UTIL_H_ */
