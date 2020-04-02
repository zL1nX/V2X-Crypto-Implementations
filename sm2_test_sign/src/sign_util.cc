#include "sign_util.h"



void sm2_log_key(const char *label, const EC_KEY *key)
{
    FILE *fp = fopen("key.txt","wb");
    if (!fp) {
        return;
    }

    fprintf(fp, "EC_KEY (%s):\n", label);
    if (EC_KEY_print_fp(fp, key, 3) == 0) {
        fprintf(stderr, "Log: error printing EC key.\n");
        return;
    }
    fflush(fp);
}

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


// p_Qc = EC_KEY_get0_public_key(ecqv_gen.ca_key);
// c = EC_KEY_get0_private_key(ecqv_gen.ca_key);

EC_KEY *sm2_read_key(FILE *file)
{
    EVP_PKEY *pk = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    EC_KEY *key = NULL;
    const EC_POINT* pubkey;
    const BIGNUM* prvkey;

    if (!pk) {
        fprintf(stderr, "Error reading private key file.\n");
        return NULL;
    }
    key = EVP_PKEY_get1_EC_KEY(pk);



    if(EC_KEY_check_key(key) == 0)
    {
        printf("key check wrong!\n");
    }
    if (!key) {
        fprintf(stderr, "Error loading EC private key.\n");
    }

    EVP_PKEY_free(pk);
    fclose(file);
    return key;
}

FILE *sm2_open_file(char *name, const char *mode)
{
    FILE *file = fopen(name, mode);

    if (!file) {
        fprintf(stderr, "Error opening file '%s': %s.\n",
                name, strerror(errno));
        return NULL;
    }

    return file;
}

EC_KEY* read_key()
{
    //char key_file[] = "/home/veins/Documents/sm2_gen_key.pem";
    char key_file[] = "/home/veins/VANETSIM/ECQV/OUTPUT/KEY/sm2_ecqv_key13.txt";
    FILE *key = sm2_open_file(key_file, "rb");
    return sm2_read_key(key);
}


unsigned char* get_digest(EC_KEY *ec_key, const char* id, const char* M)
{
    const EVP_MD *id_md = EVP_sm3();
    const EVP_MD *msg_md = EVP_sm3();
    const char Z[] = "F4A38489E32B45B6F876E3AC2168CA392362DC8F23459C1D1146FC3DBFB7BC9A";
    const char e[] = "B524F552CD82B8B028476E005C377FB19A87E6FC682D48BB5D42E3D9B9EFFE76";
    static unsigned char local_dgst[EVP_MAX_MD_SIZE];
    size_t dgstlen;

    dgstlen = sizeof(local_dgst);
    if (!SM2_compute_id_digest(id_md, id, strlen(id), local_dgst, &dgstlen, ec_key))
    {
        fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
    }

    dgstlen = sizeof(local_dgst);
    if (!SM2_compute_message_digest(id_md, msg_md, (const unsigned char *)M, strlen(M), id, strlen(id), local_dgst, &dgstlen, ec_key))
    {
        fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
    }

     return local_dgst;
}


int hexequbin(const char *hex, const unsigned char *bin, size_t binlen)
{
    int ret = 0;
    char *buf = NULL;
    size_t buflen = binlen * 2 + 1;
    size_t i = 0;


    if (binlen * 2 != strlen(hex)) {
        return 0;
    }
    if (!(buf = (char*)malloc(binlen * 2 + 1))) {
        return 0;
    }
    for (i = 0; i < binlen; i++) {
        sprintf(buf + i*2, "%02X", bin[i]);
    }
    buf[buflen - 1] = 0;

    if (memcmp(hex, buf, binlen * 2) == 0) {
        ret = 1;
    }

    free(buf);
    return ret;
}

EC_KEY* get_new_key()
{
    EC_GROUP *sm2p256test = NULL;
                sm2p256test = new_ec_group(1,
                        "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
                        "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
                        "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
                        "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
                        "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
                        "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
                        "1");
    EC_KEY* key =  new_ec_key(sm2p256test, "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263", "0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A","7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857");
    EC_GROUP_free(sm2p256test);
    return key;
}

EC_KEY* get_new_pub_key()
{
    EC_GROUP *sm2p256test = NULL;
                    sm2p256test = new_ec_group(1,
                            "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
                            "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
                            "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
                            "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
                            "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
                            "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
                            "1");
        EC_KEY* key =  new_ec_key(sm2p256test, NULL, "0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A","7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857");
        EC_GROUP_free(sm2p256test);
        return key;
}

EC_KEY *new_ec_key(const EC_GROUP *group, const char *sk, const char *xP, const char *yP)
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


int sm2_key_write(EC_KEY* my_key)
{
    EVP_PKEY *evp_pkey;
    EC_KEY *ec_key;
    FILE *out = fopen("/home/veins/Documents/sm2_gen_key.txt","wb");
    evp_pkey = EVP_PKEY_new();

    if (!evp_pkey) {
        return -1;
    }

    ec_key = EC_KEY_dup(my_key);

    if (!ec_key) {
        return -1;
    }

    if (EVP_PKEY_assign_EC_KEY(evp_pkey, ec_key) == 0) {
        return -1;
    }

    if (PEM_write_PrivateKey(out, evp_pkey,
                             NULL, NULL, 0, 0, NULL) == 0) {
        EVP_PKEY_free(evp_pkey);
        return -1;
    }

    EVP_PKEY_free(evp_pkey);
    fclose(out);
    return 0;
}

void print_hex(unsigned char* t, size_t len)
{
    // printf("Address of t is: %x\n", t);
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
