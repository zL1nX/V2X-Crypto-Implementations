/*
 * SM9Reg_util.cc
 *
 *  Created on: Mar 17, 2020
 *      Author: veins
 */


#include "SM9Reg_util.h"


char* ecqv_gen_filename(const char* head, const char *id, const char* tail)
{
    //char sid[5] = { 0 };
    int len = strlen(head) + strlen(id) + strlen(tail);
    char *name = (char*)malloc(sizeof(char)*128);
    memset(name, 0, 128);
    //sprintf(sid, "%d", id);
    strcat(name, head);
    //strcat(name, sid);
    strcat(name, tail);
    //filename = name;
    //printf("ID %d: Opening: %s\n", id, name);
    return name;

    //return filename;
}

char* bytes_to_hex(unsigned char *bytes, int len)
{
    char *s = (char*)malloc(sizeof(char)*(len*2 + 1));
    unsigned char* p = bytes;
    for(int i= 0;i<len;i++)
    {
        sprintf(s + i*2, "%02x", *p);
        p++;
    }
    p = NULL;
    return s;
}

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

int hex_write(FILE *fp, unsigned char* content, unsigned int len, const char* label)
{
    unsigned char *p = content;
    if (!fp)
    {
        return 0;
    }

    if (!content || !label)
    {
        fprintf(stderr, "Log: error storing hex.\n");
        return 0;
    }
    fprintf(fp, "%s:", label);
    for(int i = 0;i<len;i++)
    {
        fprintf(fp, "%02x", *p);
        p++;
    }
    fprintf(fp, "\n");
    //fflush(fp);
    //OPENSSL_free(content);
    fclose(fp);
    return 1;
}

int bn_write(FILE *fp, const char* label, BIGNUM *n)
{
    char *str;
    if (!fp)
    {
        return 0;
    }

    str = BN_bn2hex(n);
    if (!str)
    {
        fprintf(stderr, "Log: error converting bignum to hex.\n");
        return 0;
    }
    fprintf(fp, "%s:%s\n", label, str);
    OPENSSL_free(str);
    fclose(fp);
    return 0;
}

int get_line(const char* filename, int* len)
{
    FILE *fp = fopen(filename, "r");
    int c, lc=0; //c为文件当前字符，lc为上一个字符，供结尾判断用。
    int line = 0; //行数统计
    fseek(fp, 0, SEEK_END);
    int fsize = ftell(fp);
    rewind(fp);
    while((c = fgetc(fp)) != EOF) //逐个读入字符直到文件结尾
    {
        if(c == '\n') line ++; //统计行数。
        lc = c; //保存上一字符。
    }
    fclose(fp); //关闭文件
    if(lc != '\n') line ++;//处理末行
    *len = line;
    return fsize/line;
}

char** get_content_by_line(const char* filename, int len, int len_size, unsigned char *buf)
{
    printf("%d\n%d\n", len, len_size);

    char **content;
    content = (char**)malloc(len*len_size*sizeof(char));
    FILE *fp = fopen(filename, "r");
    if(fp == NULL)
    {
        return NULL;
    }
    for(int i = 0; i<len;i++)
    {
        content[i] = (char*)malloc(len_size*sizeof(char));
        fscanf(fp, "%s", content[i]);

    }
    fclose(fp);
    return content;
}

const char* search_content(char** content, unsigned char* buf, int hlen, int len, int len_size)
{
    char **idval, **hashval, *result;
    char *target = bytes_to_hex(buf, hlen);
    int id_size = len_size - 64;
    idval = (char**)malloc(len*id_size*sizeof(char));
    hashval = (char**)malloc(len*65*sizeof(char));
    result = (char*)malloc(id_size * sizeof(char));
    for(int i = 0;i<len;i++)
    {
        idval[i] = (char*)malloc(id_size*sizeof(char));
        hashval[i] = (char*)malloc(65*sizeof(char));
        sscanf(content[i], "%[^:]:%[^:]", idval[i], hashval[i]);
    }
    for(int i = 0;i<len;i++)
    {

        const char* sample = hashval[i];
        if(strcmp(hashval[i], target) == 0)
        {
            memcpy(result, idval[i], sizeof(char) * id_size);
        }

        free(hashval[i]);
        free(idval[i]);
        free(content[i]);
    }
    free(hashval);
    free(idval);
    free(content);
    free(target);
    printf("result: %s\n", result);
    return result;


}

const char* Search_Identity(unsigned char* buf, int hlen)
{
    const char* filename = "/home/veins/workspace.omnetpp/sm9_test_register/identity_tuple.txt";
    int len = 0, len_size = get_line(filename, &len);
    const char *userid = NULL;
    char **content = get_content_by_line(filename, len, len_size, buf);
    if(!(userid = search_content(content, buf, hlen, len, len_size)))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    return userid;
}


int rate_pairing_calculate(struct SM9_REG_PARAM_T PubParams, unsigned char** buf, EC_POINT *P1, BIGNUM *t1, point_t *P2, BIGNUM *t2, BIGNUM *r)
{
    fp12_t w;
    unsigned char w_bin[384];
    BN_CTX *ctx = BN_CTX_new();

    if(P1 == NULL)
    {
        if(t1 == NULL)
        {
            //P1 = EC_GROUP_get0_generator(PubParams.group);
        }
        else
        {
            P1 = EC_POINT_new(PubParams.group);
            if(!EC_POINT_mul(PubParams.group, P1, t1, NULL, NULL, ctx))
            {
               return 0;
            }
        }
    }
    else
    {
        if(!t1)
        {
            if(!EC_POINT_mul(PubParams.group, P1, t1, NULL, NULL, ctx))
            {
               return 0;
            }
        }
    }

    if(P2 == NULL)
    {
        if(!point_init(P2, ctx))
        {
            return 0;
        }
        if(t2)
        {
            if(!point_mul_generator(P2, t2, PubParams.p, ctx))
            {
                return 0;
            }
        }
    }
    else
    {
        if(t2)
        {
            if(!point_mul_generator(P2, t2, PubParams.p, ctx))
            {
                return 0;
            }
        }
    }
    if(!fp12_init(w, ctx) || !rate_pairing(w, P2, P1, ctx))
    {
        return 0;
    }
    if(r && fp12_pow(w, w, r, PubParams.p, ctx)) {}

    if(!fp12_to_bin(w, w_bin))
    {
        return 0;
    }
    *buf = w_bin;

    if(ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if(P1)
    {
        EC_POINT_free(P1);
    }
    if(t1)
    {
        BN_free(t1);
    }
    if(t2)
    {
        BN_free(t2);
    }
    if(r)
    {
        BN_free(r);
    }
    return 1;
}



double Calc_Last_Distance(struct SM9_RSU_REG_T rsu_struct)
{
    //unsigned char *last_rlp = rsu_struct.RLP;
    // consider about the RLP structure --  we'd better perform only one operation to get the real RSU
    //
    /* the old way O(n)
     * for i from 1 to len(RSUparams)
     *      calc(Hash(R[i]))
     *      if calc == last_rlp
     *          break;
     * double* last_pos = get_RSU_pos(R[i]);
     * distance = ((x_last - x_new)^2 + (y_last - y_new)^2)^(0.5)
     * return distance;
     *
     * the new way O(logn)
     * last_RSU = some_operation(last_rlp);
     * double* last_pos = get_RSU_pos(R[i]);
     * distance = ((x_last - x_new)^2 + (y_last - y_new)^2)^(0.5)
     * return distance;
     */
    return 10.0;
}

int Calc_New_RLP(struct SM9_RSU_REG_T rsu_struct, unsigned char** rlp)
{
    const char *test = "8F0FC0E15F6B1FC7937F3C53C8D206CAEAB88E725ADFBDB1AFD8CA436C9CC036", *p=test;
    unsigned char *new_rlp = (unsigned char*)malloc(sizeof(char) * HASH_LENGTH);
    /*for(int i = 0;i<64;i++)
        new_rlp[i] = *p++;*/
    memcpy(new_rlp, p, sizeof(char)*HASH_LENGTH);
    /*
     * the old way
     * new_RLP = hash(current_rsu || pos, N)
     * return new_RLP
     */
    *rlp = new_rlp;

    return 1;

}


int Enc_RLP(unsigned char* new_rlp, BIGNUM* krj, const char* idA, struct SM9_REG_PARAM_T PubParams, unsigned char** cyphertxt, unsigned char **kra)
{
    unsigned char *bin_key = (unsigned char*)malloc(sizeof(char) * 16);
    BN_CTX *ctx = BN_CTX_new();
    fp12_t w2;
    point_t P2;
    BIGNUM *Trj = BN_new(), *t2 = NULL;
    unsigned char buf2[384];
    unsigned char *p = NULL;
    int hlen = 0;

    //calc key
    BN_CTX_start(ctx);
    if(!point_init(&P2, ctx) || !fp12_init(w2, ctx))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!SM9_hash1(PubParams.md, &t2, idA, strlen(idA), PubParams.hid, PubParams.n, ctx))
    {
        SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_SM9_LIB);
        return 0;
    }
    if(!BN_mod_mul(Trj, krj, t2, PubParams.n, ctx) || !point_mul_generator(&P2, Trj, PubParams.p, ctx)) // calculate the number before the P1 first
    {
        SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_INVALID_POINTPPUB);
        return 0;
    }
    if(!rate_pairing(w2, &P2, EC_GROUP_get0_generator(PubParams.group), ctx) || ! fp12_to_bin(w2, buf2))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_PAIRING_ERROR);
        return 0;
    }
    //print_hex("A:buf", buf2, 384);
    // K = e(P1, TrjP2), need to generate the Key material with 256 bit size
    if(!PKCS5_PBKDF2_HMAC(idA, strlen(idA), buf2, 384, 4096, EVP_sm3(), 16, bin_key))
    {
        return 0;
    }

    print_hex("bin_key", bin_key, SM4_ENC_KEY_SIZE);
    *kra = bin_key;
    //bin_key contains our key
    if(!_sms4_enc(bin_key, idA, new_rlp, cyphertxt, HASH_LENGTH))
    {
        return 0;
    }
    //*cyphertxt = bin_key;

    if(ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if(t2 && Trj)
    {
        BN_free(Trj);
        BN_free(t2);
    }
    //free(bin_key);
    return 1;
}


int sms4_enc(unsigned char* key, const char* idA, unsigned char* plain, unsigned char **cypher, int plen)
{
    int ilen = strlen(idA);
    unsigned char *ctext = (unsigned char*)malloc(sizeof(char) * plen);
    //unsigned char ctext[plen + 1];
    unsigned char iv[ilen];
    const char *pid;
    sms4_key_t sms4_key;
    printf("LOG: In %s-%d, LEN: %d %d\n", __FUNCTION__, __LINE__, plen, ilen);
    //memcpy(iv, idA, ilen);
    pid = idA;
    for(int i = 0;i<ilen;i++) iv[i] = *pid++;
    print_hex("sms4_enc-plaintext", plain, plen);
    print_hex("sms4_enc-bin_key", key, SM4_ENC_KEY_SIZE);
    sms4_set_encrypt_key(&sms4_key, key);
    sms4_cbc_encrypt(plain, ctext, plen, &sms4_key, iv, 1);
    //print_hex("sms4_enc-cyphertxt", ctext, 64);
    *cypher = ctext;
    free(plain);
    return 1;
}




int Calc_Enc_Key(unsigned char *Prj, struct SM9_REG_PARAM_T PubParams, const char* idA, unsigned char** fp12_key)
{
    printf("LOG: In %s-%d\n", __FUNCTION__, __LINE__);
    unsigned char buf3[384];
    unsigned char *bin_key = (unsigned char*)malloc(sizeof(char) * 16);
    BIGNUM *t2 = NULL;
    int hlen = 0;
    BN_CTX *ctx = BN_CTX_new();
    fp12_t w3;
    EC_POINT *P1 = EC_POINT_new(PubParams.group);
    point_t P2;

    //print_hex("B:Prj", Prj, 129);

    BN_CTX_start(ctx);
    if(!point_init(&P2, ctx) || !point_from_octets(&P2, Prj, PubParams.p, ctx) || !fp12_init(w3, ctx))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!SM9_hash1(PubParams.md, &t2, idA, strlen(idA), PubParams.hid, PubParams.n, ctx))
    {
        SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_SM9_LIB);
        return 0;
    }
    if(!EC_POINT_mul(PubParams.group, P1, t2, NULL, NULL, ctx)) // calculate the number before the P1 first
    {
        SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_INVALID_POINTPPUB);
        return 0;
    }
    if(!rate_pairing(w3, &P2, P1, ctx) || ! fp12_to_bin(w3, buf3))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_PAIRING_ERROR);
        return 0;
    }
    //print_hex("B:buf", buf3, 384);
    if(!PKCS5_PBKDF2_HMAC(idA, strlen(idA), buf3, 384, 4096, EVP_sm3(), 16, bin_key))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    print_hex("B:bin_key", bin_key, 16);
    *fp12_key = bin_key;

    if(ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    EC_POINT_free(P1);
    if(t2)
    {
        BN_free(t2);
    }
    return 1;
}

int Check_Cypher(unsigned char *key_buf, const char *idA, unsigned char *cypher, unsigned char **new_rlp)
{
    printf("LOG: In %s-%d\n", __FUNCTION__, __LINE__);
    //unsigned char *plain = (unsigned char*)malloc(sizeof(char) * 64);

    if(!sms4_dec(key_buf, idA, cypher, new_rlp, HASH_LENGTH) || !new_rlp)
    {
        return 0;
    }
    //*new_rlp = plain;
    //free(key_buf);
    //print_hex("plain", plain, 64);
    return 1;
}

int sms4_dec(unsigned char* key, const char* idA, unsigned char* cypher, unsigned char **plain, int clen)
{
    int ilen = strlen(idA);
    unsigned char *ptext = (unsigned char*)malloc(sizeof(char) * clen);
    unsigned char iv[ilen];
    const char *pid = idA;
    sms4_key_t sms4_key;
    for(int i = 0;i<ilen;i++) iv[i] = *pid++;
    sms4_set_decrypt_key(&sms4_key, key);
    sms4_cbc_encrypt(cypher, ptext, clen, &sms4_key, iv, 0);
    *plain = ptext;
    print_hex("sms4_dec-plaintext", ptext, clen);
    //free(cypher);
    return 1;
}

int Calc_PrivateKey(char **dsa, char **dsra, BIGNUM *krj, BIGNUM *ks, const char *idA, struct SM9_REG_PARAM_T PubParams)
{

    BIGNUM *t1 = NULL, *t2 = NULL;
    EC_POINT *regionKey = EC_POINT_new(PubParams.group);
    EC_POINT *memberKey = EC_POINT_new(PubParams.group); // dsra, dsa respectively


    BN_CTX *ctx = BN_CTX_new();

    BN_CTX_start(ctx);
    // t1 = H1(SID || hid, N) t2 = H1(IDA || hid, N)
    if (!SM9_hash1(PubParams.md, &t1, PubParams.sid, strlen(PubParams.sid), PubParams.hid, PubParams.n, ctx))
    {
        SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_SM9_LIB);
        return 0;
    }
    if (!SM9_hash1(PubParams.md, &t2, idA, strlen(idA), PubParams.hid, PubParams.n, ctx))
    {
        SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_SM9_LIB);
        return 0;
    }
    // t1 = t1 + ks t2 = t2 + ks
    if (!BN_mod_add(t1, t1, ks, PubParams.n, ctx) || !BN_mod_add(t2, t2, ks, PubParams.n, ctx))
    {
        SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_BN_LIB);
        return 0;
    }
    // if t1 or t2 is zero, return failed
    if (BN_is_zero(t1) || BN_is_zero(t2))
    {
        SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, SM9_R_ZERO_ID);
        return 0;
    }
    // d1 = (H1(SID || hid, N) + ks) ^ -1, d2 = (H1(IDA || hid, N) + ks) ^ -1
    if (!BN_mod_inverse(t1, t1, PubParams.n, ctx) || !BN_mod_inverse(t2, t2, PubParams.n, ctx))
    {
        SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_BN_LIB);
        return 0;
    }
    // d1' = [krj][d1] d2' = [krj][d2]
    if (!BN_mod_mul(t1, krj, t1, PubParams.n, ctx) || !BN_mod_mul(t2, krj, t2, PubParams.n, ctx))
    {
        SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_BN_LIB);
        return 0;
    }
    // dsa = [d2']P1 dsra = [krj][d1]dsa = [krj][d1][d2']P1 = [d1'][d2']P1
    if(!EC_POINT_mul(PubParams.group, memberKey, t2, NULL, NULL, ctx))
    {
        SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_SM9_LIB);
        EC_POINT_free(memberKey);
        return 0;
    }
    //d1'' = [d1'][d2'] dsra = [d1'']P1
    if(!BN_mod_mul(t1, t2, t1, PubParams.n, ctx) || !EC_POINT_mul(PubParams.group, regionKey, t1, NULL, NULL, ctx))
    {
        SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_SM9_LIB);
        EC_POINT_free(regionKey);
        return 0;
    }

    *dsa = EC_POINT_point2hex(PubParams.group, memberKey, POINT_CONVERSION_UNCOMPRESSED, ctx);
    *dsra = EC_POINT_point2hex(PubParams.group, regionKey, POINT_CONVERSION_UNCOMPRESSED, ctx);

    if(ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if(t1)
    {
        BN_free(t1);
    }
    if(t2)
    {
        BN_free(t2);
    }
    EC_POINT_free(memberKey);
    EC_POINT_free(regionKey);

    return 1;
}

int Enc_KEY(char *private_key, unsigned char **cyphertxt, unsigned char *Kra, const char *idA)
{
    //unsigned char *plain = (unsigned char*)malloc(sizeof(char) * (2 * EC_POINT_HEX_LENGTH));
    unsigned char *plain = (unsigned char*)malloc(sizeof(char) * 2 * EC_POINT_HEX_LENGTH);
    unsigned char *key = (unsigned char*)malloc(sizeof(char) * SM4_ENC_KEY_SIZE);
    //unsigned char plain[2 * EC_POINT_HEX_LENGTH];
    // it's ok here 2020.3.27.11.34
    //memcpy(plain, private_key, sizeof(char) * 2 * EC_POINT_HEX_LENGTH );
    for(int i = 0; i < 2 * EC_POINT_HEX_LENGTH;i++)
    {
        plain[i] = private_key[i];
    }
    for(int i = 0;i < SM4_ENC_KEY_SIZE;i++)
    {
        key[i] = Kra[i];
    }
    print_hex("B:plaintxt", plain, 2 * EC_POINT_HEX_LENGTH);
    if(!sms4_enc(key, idA, plain, cyphertxt, 2 * EC_POINT_HEX_LENGTH))
    {
        return 0;
    }
    free(key);
    //*cyphertxt = plain;
    return 1;
}

int _sms4_enc(unsigned char* key, const char* idA, unsigned char* plain, unsigned char **cypher, int plen)
{
    int ilen = strlen(idA);
    unsigned char *ctext = (unsigned char*)malloc(sizeof(char) * plen); // plen + 1 not ok
    //unsigned char ctext[plen]; // it's ok here
    unsigned char iv[ilen];
    const char *pid;
    sms4_key_t sms4_key;
    printf("LOG: In %s-%d, LEN: %d %d\n", __FUNCTION__, __LINE__, plen, ilen);
    //memcpy(iv, idA, ilen);
    pid = idA;
    for(int i = 0;i<ilen;i++) iv[i] = *pid++;
    print_hex("Key:sms4_enc-plaintext", plain, plen);
    print_hex("Key:sms4_enc-bin_key", key, SM4_ENC_KEY_SIZE);
    sms4_set_encrypt_key(&sms4_key, key);
    sms4_cbc_encrypt(plain, ctext, plen, &sms4_key, iv, 1);
    print_hex("Key:sms4_enc-cyphertxt", ctext, plen);
    *cypher = ctext;
    free(plain);
    return 1;
}

int Dec_Key(struct SM9_RSU_REG_T t, unsigned char *key, const char* idA, char** dsa, char** dsra)
{
    unsigned char *plain = NULL;
    const char *mode = "04";
    char *memberKey = (char*)malloc(sizeof(char)*EC_POINT_HEX_LENGTH + 3); // 04 + content
    char *regionKey = (char*)malloc(sizeof(char)*EC_POINT_HEX_LENGTH + 3);
    char *p = NULL;
    memcpy(memberKey, mode, sizeof(char)*2);
    memcpy(regionKey, mode, sizeof(char)*2);
    if(!sms4_dec(key, idA, t.enc_buf, &plain, 2 * EC_POINT_HEX_LENGTH))
    {
        return 0;
    }
    print_hex("B:Key plain", plain, 2 * EC_POINT_HEX_LENGTH);
    memcpy(memberKey + 2, plain, sizeof(char)*EC_POINT_HEX_LENGTH);memberKey[EC_POINT_HEX_LENGTH+2]='\0';
    memcpy(regionKey + 2, plain + 128, sizeof(char)*EC_POINT_HEX_LENGTH);regionKey[EC_POINT_HEX_LENGTH+2]='\0';
    *dsa = memberKey;
    *dsra = regionKey;

    printf("dsa: %s\ndsra: %s\n", *dsa, *dsra);
    /*p = *dsa;
    for(int i=0;i<EC_POINT_HEX_LENGTH + 2;i++)
        printf("%02x", *p++);
    printf("\n");

    p = *dsra;
    for(int i=0;i<EC_POINT_HEX_LENGTH + 2;i++)
            printf("%02x", *p++);
    printf("\n");*/
    free(plain);
    return 1;
}
