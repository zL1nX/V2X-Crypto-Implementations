/*
 * SM9Sign_util.cc
 *
 *  Created on: Mar 16, 2020
 *      Author: veins
 */
#include "SM9Sign_util.h"

void print_hex(const char* label, unsigned char* h, size_t len)
{
    unsigned char* p = h;
    printf("%s: ", label);
    for(int i=0;i<len;i++)
    {
        printf("%02x", *p);
        p++;
    }
    printf("\n");
    p = NULL;
}

void print_bn(const char* label, const BIGNUM* bn)
{
    printf("%s: ", label);
    char *hex = NULL;
    if((hex = BN_bn2hex(bn)))
    {
        printf("%s\n", hex);
    }
    OPENSSL_free(hex);
}

