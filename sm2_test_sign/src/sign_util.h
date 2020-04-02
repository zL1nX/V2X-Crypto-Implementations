/*
 * sign_util.h
 *
 *  Created on: Dec 26, 2019
 *      Author: veins
 */

#ifndef SIGN_UTIL_H_
#define SIGN_UTIL_H_

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
#include <mygmssl/crypto/sm2/sm2_lcl.h>


EC_KEY* read_key();
FILE *sm2_open_file(char *name, const char *mode);
EC_KEY *sm2_read_key(FILE *file);
EC_GROUP *new_ec_group(int is_prime_field,
    const char *p_hex, const char *a_hex, const char *b_hex,
    const char *x_hex, const char *y_hex, const char *n_hex, const char *h_hex);

unsigned char* get_digest(EC_KEY *ec_key, const char* id, const char* M);
int hexequbin(const char *hex, const unsigned char *bin, size_t binlen);
EC_KEY *new_ec_key(const EC_GROUP *group, const char *sk, const char *xP, const char *yP);
EC_KEY* get_new_key();
EC_KEY* get_new_pub_key();
int sm2_key_write(EC_KEY* my_key);
void print_hex(unsigned char* t, size_t len);
void print_bignum(char flag, const BIGNUM* n);
void sm2_log_key(const char *label, const EC_KEY *key);
#endif /* SIGN_UTIL_H_ */
