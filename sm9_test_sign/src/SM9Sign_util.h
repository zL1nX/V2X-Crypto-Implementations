/*
 * SM9Sign_util.h
 *
 *  Created on: Mar 16, 2020
 *      Author: veins
 */

#ifndef SM9SIGN_UTIL_H_
#define SM9SIGN_UTIL_H_

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

struct SM9Sig_t
{
    unsigned char sig[256]; // including the h and S
    unsigned char msg[100]; // message
    int siglen;
};

void print_hex(const char* label, unsigned char* h, size_t len);
void print_bn(const char* label, const BIGNUM* bn);

#endif /* SM9SIGN_UTIL_H_ */
