/*
 * SM9_SignUtil.cc
 *
 *  Created on: Mar 30, 2020
 *      Author: veins
 */
#include "SM9_SignUtil.h"

void print_hex(const char* label, unsigned char* h, size_t len)
{
    unsigned char* p = h;
    printf("%s: ", label);
    for(int i=0;i<len;i++)
    {
        printf("%02x", *p++);
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

BIGNUM* generate_random_number()
{
    const BIGNUM *n = SM9_get0_order();
    BIGNUM *r = BN_new();

    do {
        if (!BN_rand_range(r, n)) {
            SM9err(SM9_F_SM9_GENERATE_MASTER_SECRET, ERR_R_BN_LIB);
        }
    } while (BN_is_zero(r));
    return r;
}

char* get_filename(const char *id)
{
    const char *path = "/home/veins/VANETSIM/SM9REG/";
    const char *type = ".txt";
    int name_len = strlen(path) + strlen(id) + strlen(type) + 1;
    char *filename=(char*)malloc(sizeof(char)*name_len);
    memset(filename, 0, name_len);
    strcpy(filename, path);
    strcat(filename, id);
    strcat(filename, type);
    printf("Filename: %s\n", filename);
    return filename;
}

int read_sign_params(char *filename, struct SM9_SIG_PARAM_T *params)
{
    //struct SM9_SIG_PARAM_T reader;
    char *dsa = (char*)malloc(sizeof(char)*(EC_POINT_HEX_LENGTH + 3));
    char *dsra = (char*)malloc(sizeof(char)*(EC_POINT_HEX_LENGTH + 3));
    unsigned char *point_rj = (unsigned char*)malloc(sizeof(char)*129);
    unsigned char *point_pubs = (unsigned char*)malloc(sizeof(char)*130);
    unsigned char *q;
    char p[260];
    FILE *fp = fopen(filename, "rb");
    if(!fp)
    {
        fprintf(stderr, "Error opening file '%s': %s.\n", filename, strerror(errno));
        return 0;
    }

    fscanf(fp, "%s\n", dsa);
    fscanf(fp, "%s\n", dsra);
    //printf("dsa: %s\ndsra: %s\n", dsa, dsra);
    fscanf(fp,"%s\n", p);q = point_rj;
    for(int i = 0;i < 129 ;i++)
    {
        sscanf(p + 2*i, "%02hhx", q + i);
    }
    fscanf(fp,"%s\n", p);q = point_pubs;
    for(int i = 0;i < 129 ;i++)
    {
        sscanf(p + 2*i, "%02hhx", q + i);
    }
    //print_hex("prj", point_rj, 129);
    //print_hex("pubs", point_pubs, 129);

    params->dsa = dsa;
    params->dsra = dsra;
    params->Prj_hex = point_rj;
    params->Pubs_hex = point_pubs;

    fclose(fp);
    free(filename);
    return 1;
}


int SM9_hash2(const EVP_MD *md, BIGNUM **H, const char *msg, int msglen, unsigned char *buf0, const BIGNUM *n, BN_CTX *ctx)
{
    int ret = 0;
    BIGNUM *h = NULL;
    BN_CTX *bn_ctx = NULL;
    EVP_MD_CTX *ctx1 = NULL;
    EVP_MD_CTX *ctx2 = NULL;
    unsigned char prefix[1] = {0x02};
    unsigned char ct1[4] = {0x00, 0x00, 0x00, 0x01};
    unsigned char ct2[4] = {0x00, 0x00, 0x00, 0x02};
    unsigned char buf[128];
    unsigned int len;

    if (!(ctx1 = EVP_MD_CTX_new())
        || !(ctx2 = EVP_MD_CTX_new())
        || !(bn_ctx = BN_CTX_new())
        || !(h = BN_new())) {
        return 0;
    }

    if (!EVP_DigestInit_ex(ctx1, md, NULL))
    {
        SM9err(SM9_F_SM9_SIGNINIT, ERR_R_EVP_LIB);
        return 0;
    }
    if (!EVP_DigestUpdate(ctx1, prefix, sizeof(prefix)))
    {
        SM9err(SM9_F_SM9_SIGNINIT, ERR_R_EVP_LIB);
        return 0;
    }
    if (!EVP_DigestUpdate(ctx1, buf0, sizeof(buf0)) || !EVP_MD_CTX_copy(ctx2, ctx1)
                /* Ha1 = Hv(0x02||M||w||0x00000001) */
        || !EVP_DigestUpdate(ctx1, ct1, sizeof(ct1))
                /* Ha2 = Hv(0x02||M||w||0x00000002) */
        || !EVP_DigestUpdate(ctx2, ct2, sizeof(ct2))
        || !EVP_DigestFinal_ex(ctx1, buf0, &len)
        || !EVP_DigestFinal_ex(ctx2, buf0 + len, &len))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_DIGEST_FAILURE);
        return 0;
    }

            /* Ha = Ha1||Ha2[0..7] */
    if (!BN_bin2bn(buf0, 40, h)
        /* h = (Ha mod (n - 1)) + 1 */
        || !BN_mod(h, h, SM9_get0_order_minus_one(), bn_ctx)
        || !BN_add_word(h, 1))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, ERR_R_BN_LIB);
        return 0;
    }

    *H = h;

    if(bn_ctx)
    {
        BN_CTX_free(bn_ctx);
    }
    if(ctx1)
    {
        EVP_MD_CTX_free(ctx1);
    }
    if(ctx2)
    {
        EVP_MD_CTX_free(ctx2);
    }
    return 1;
}
