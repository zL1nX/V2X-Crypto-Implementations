/*
 * kap_util.cc
 *
 *  Created on: Dec 30, 2019
 *      Author: veins
 */
#include "kap_util.h"

const char rnd_seed[] = "this is a string for making the random number have entropy";
const char *rnd_number = NULL;
RAND_METHOD fake_rand;
const RAND_METHOD *old_rand;


EC_GROUP *new_ec_group(int is_prime_field,
    const char *p_hex, const char *a_hex, const char *b_hex,
    const char *x_hex, const char *y_hex, const char *n_hex, const char *h_hex)
{
    int ok = 0;
    EC_GROUP *group = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BIGNUM *n = NULL;
    BIGNUM *h = NULL;
    EC_POINT *G = NULL;
    point_conversion_form_t form = SM2_DEFAULT_POINT_CONVERSION_FORM;
    int flag = 0;

    if (!(ctx = BN_CTX_new())) {
        goto err;
    }

    if (!BN_hex2bn(&p, p_hex) ||
        !BN_hex2bn(&a, a_hex) ||
        !BN_hex2bn(&b, b_hex) ||
        !BN_hex2bn(&x, x_hex) ||
        !BN_hex2bn(&y, y_hex) ||
        !BN_hex2bn(&n, n_hex) ||
        !BN_hex2bn(&h, h_hex)) {
        goto err;
    }

    if (is_prime_field) {
        if (!(group = EC_GROUP_new_curve_GFp(p, a, b, ctx))) {
            goto err;
        }
        if (!(G = EC_POINT_new(group))) {
            goto err;
        }
        if (!EC_POINT_set_affine_coordinates_GFp(group, G, x, y, ctx)) {
            goto err;
        }
    } else {
        if (!(group = EC_GROUP_new_curve_GF2m(p, a, b, ctx))) {
            goto err;
        }
        if (!(G = EC_POINT_new(group))) {
            goto err;
        }
        if (!EC_POINT_set_affine_coordinates_GF2m(group, G, x, y, ctx)) {
            goto err;
        }
    }

    if (!EC_GROUP_set_generator(group, G, n, h)) {
        goto err;
    }

    EC_GROUP_set_asn1_flag(group, flag);
    EC_GROUP_set_point_conversion_form(group, form);

    ok = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(n);
    BN_free(h);
    EC_POINT_free(G);
    if (!ok && group) {
        ERR_print_errors_fp(stderr);
        EC_GROUP_free(group);
        group = NULL;
    }

    return group;
}

EC_KEY *sm2kap_read_key(FILE *file)
{
    EVP_PKEY *pk = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    EC_KEY *key = NULL;

    if (!pk) {
        fprintf(stderr, "Error reading private key file.\n");
        return NULL;
    }

    key = EVP_PKEY_get1_EC_KEY(pk);

    if (!key) {
        fprintf(stderr, "Error loading EC private key.\n");
    }

    EVP_PKEY_free(pk);
    fclose(file);
    return key;
}

FILE *sm2kap_open_file(char const* name, const char *mode)
{
    FILE *file = fopen(name, mode);

    if (!file) {
        fprintf(stderr, "Error opening file '%s': %s.\n",
                name, strerror(errno));
        return NULL;
    }

    return file;
}

EC_KEY* read_key(char const* key_file)
{
    FILE *key = sm2kap_open_file(key_file, "rb");
    return sm2kap_read_key(key);
}

void shared_key_write(unsigned char *key, int key_len, char *file_name)
{
    FILE *wfile = sm2kap_open_file(file_name, "wb");
    for(int i = 0;i < key_len;i++)
    {
        fprintf(wfile, "%02x", *key);
        key++;
    }
    fflush(wfile);
    //fwrite(key, sizeof(unsigned char), key_len, wfile);
    fclose(wfile);
}

int fbytes(unsigned char *buf, int num)
{
    int ret = 0;
    BIGNUM *bn = NULL;

    if (!BN_hex2bn(&bn, rnd_number)) {
        goto end;
    }
    if (BN_num_bytes(bn) > num) {
        goto end;
    }
    memset(buf, 0, num);
    if (!BN_bn2bin(bn, buf + num - BN_num_bytes(bn))) {
        goto end;
    }
    ret = 1;
end:
    BN_free(bn);
    return ret;
}


int change_rand(const char *hex)
{
    if (!(old_rand = RAND_get_rand_method())) {
        return 0;
    }

    fake_rand.seed      = old_rand->seed;
    fake_rand.cleanup   = old_rand->cleanup;
    fake_rand.add       = old_rand->add;
    fake_rand.status    = old_rand->status;
    fake_rand.bytes     = fbytes;
    fake_rand.pseudorand    = old_rand->bytes;

    if (!RAND_set_rand_method(&fake_rand)) {
        return 0;
    }

    rnd_number = hex;
    return 1;
}

int restore_rand(void)
{
    rnd_number = NULL;
    if (!RAND_set_rand_method(old_rand))
        return 0;
    else    return 1;
}

char* get_id(char const* idfile)
{
    printf("here!\n");
    FILE *id = fopen(idfile, "rb");
    fseek(id, 0, SEEK_END);
    size_t fileLen = ftell(id);
    //char content[fileLen+1];
    char *content = (char *) malloc(sizeof(char) * (fileLen + 1));
    fseek(id, 0, SEEK_SET);
    fread(content, fileLen, sizeof(char), id);
    *(content + fileLen) = '\0';
    fclose(id);
    return content;
}

void print_hex(unsigned char* t, size_t len)
{
    printf("Address of t is: %x\n", t);
    unsigned char* temp = t;
    for(int i=0;i<len;i++)
    {
        printf("%02x", *temp);
        temp++;
    }
    temp = NULL;
    printf("\n\n");
}

void print_bignum(char flag, const BIGNUM* n)
{
    printf("%c: ", flag);
    char *s = BN_bn2hex(n);
    printf("%s\n", s);
    OPENSSL_free(s);
}

EC_KEY *new_ec_key(const EC_GROUP *group,
    const char *sk, const char *xP, const char *yP)
{
    int ok = 0;
    EC_KEY *ec_key = NULL;
    BIGNUM *d = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;

    OPENSSL_assert(group);
    OPENSSL_assert(xP);
    OPENSSL_assert(yP);

    if (!(ec_key = EC_KEY_new())) {
        goto end;
    }
    if (!EC_KEY_set_group(ec_key, group)) {
        goto end;
    }

    if (sk) {
        if (!BN_hex2bn(&d, sk)) {
            goto end;
        }
        if (!EC_KEY_set_private_key(ec_key, d)) {
            goto end;
        }
    }

    if (xP && yP) {
        if (!BN_hex2bn(&x, xP)) {
            goto end;
        }
        if (!BN_hex2bn(&y, yP)) {
            goto end;
        }
        if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
            goto end;
        }
    }

    ok = 1;
end:
    if (d) BN_free(d);
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (!ok && ec_key) {
        ERR_print_errors_fp(stderr);
        EC_KEY_free(ec_key);
        ec_key = NULL;
    }
    return ec_key;
}

EC_KEY* test_key(int peer, int type)
{
    EC_GROUP *sm2p256test = new_ec_group(1,
            "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
            "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
            "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
            "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
            "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
            "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
            "1");
    const char* xp = NULL;
    const char* yp = NULL;
    const char* d = NULL;
    if(peer == 1)
    {
        xp = "3099093BF3C137D8FCBBCDF4A2AE50F3B0F216C3122D79425FE03A45DBFE1655";
        yp = "3DF79E8DAC1CF0ECBAA2F2B49D51A4B387F2EFAF482339086A27A8E05BAED98B";
        d = "6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE";
    }
    else if(peer == 2)
    {
        xp = "245493D446C38D8CC0F118374690E7DF633A8A4BFB3329B5ECE604B2B4F37F43";
        yp = "53C0869F4B9E17773DE68FEC45E14904E0DEA45BF6CECF9918C85EA047C60A4C";
        d = "5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53";
    }

    if(type == 1)
        return new_ec_key(sm2p256test, d, xp, yp);
    else
        return new_ec_key(sm2p256test, NULL, xp, yp);
}


