/*
 * sm9_sign_mod.cc
 *
 *  Created on: Mar 30, 2020
 *      Author: veins
 */


#include "SM9_SignUtil.h"
#include "SM9ModSign_m.h"
#include "sm9_sign_mod.h"

//SM9ModSignature




Define_Module(A);
Define_Module(B);

void A::initialize(void)
{
    if(!SM9_ModSign_Setup(&SigParams))
    {
        ERR_print_errors_fp(stderr);
        return;
    }
    SM9ModSignature *init_reminder = new SM9ModSignature("initialized");
    scheduleAt(simTime(), init_reminder);
}


void A::handleMessage(cMessage *msg)
{
    if(msg->isSelfMessage())
    {
        if(strcmp(msg->getName(), "initialized") == 0)
        {
            //sk = generatePrivateKey(mpk, msk);
            //print_bn("ks", msk->masterSecret);
            //SM9Sign(sk, sig, &siglen);
            //print_hex("Sig After Sign", sig, siglen);
            print_hex("init Ppubs", SigParams.Pubs_hex, 129);
            if(SM9_ModSign(&SigParams, &ModSignature))
            {
                SM9ModSignature *sign_reminder = new SM9ModSignature("signed");
                scheduleAt(simTime(), sign_reminder);
            }
        }
        else if(strcmp(msg->getName(), "signed") == 0)
        {
            /*if(!SM9SendSig(ModSignature))
            {
                ERR_print_errors_fp(stderr);
            }*/
        }
        delete msg;
    }
    else
    {
        SM9ModSignature *SM9SignMsg = check_and_cast<SM9ModSignature *>(msg);
        if(strcmp(SM9SignMsg->getName(), "SM9 Verifying") == 0)
        {
            SM9ModSignature *SM9RespMsg = new SM9ModSignature("SM9 Response");
            if(!SM9SendResponse(SM9RespMsg))
            {
                ERR_print_errors_fp(stderr);
            }
        }
        delete SM9SignMsg;
    }

}

int A::SM9_ModSign_Setup(struct SM9_SIG_PARAM_T *SigParams)
{

    struct SM9_SIG_PARAM_T params;
    char *filename = get_filename(idA);
    if(!read_sign_params(filename, &params))
    {
        return 0;
    }

    //printf("dsa: %s\ndsra: %s\n", params.dsa, params.dsra);
    //print_hex("Prj", params.Prj_hex, EC_POINT_HEX_LENGTH+1);
    //print_hex("Ppubs", params.Pubs_hex, EC_POINT_HEX_LENGTH+1);
    *SigParams = params;
    return 1;
}

int A::SM9_ModSign(struct SM9_SIG_PARAM_T *SigParams, struct SM9_MOD_SIG_T *ModSignature)
{
    BIGNUM *r1 = generate_random_number();
    BIGNUM *r2 = generate_random_number();

    EC_POINT *dsa_p = EC_POINT_new(PubParams.group), *dsra_p = EC_POINT_new(PubParams.group);
    EC_POINT *S1 = EC_POINT_new(PubParams.group), *S2 = EC_POINT_new(PubParams.group);
    point_t Prj, Ppubs, P3, P2;
    fp12_t w0;
    unsigned char buf0[384];
    BIGNUM *h, *h2, *sub = BN_new(), *r2_inv = BN_new();

    BN_CTX *ctx = BN_CTX_new();

    BN_CTX_start(ctx);
    // converting the bytes to point_t
    if(!fp12_init(w0, ctx) || !point_init(&Prj, ctx) || !point_init(&Ppubs, ctx) || !point_init(&P2, ctx) || !point_init(&P3, ctx))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if(!point_from_octets(&Prj, SigParams->Prj_hex, PubParams.p, ctx) || !point_from_octets(&Ppubs, SigParams->Pubs_hex, PubParams.p, ctx))
    {
        SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_SM9_LIB);
        return 0;
    }

    // converting the bytes to key point
    if(!EC_POINT_hex2point(PubParams.group, SigParams->dsa, dsa_p, ctx) || !EC_POINT_hex2point(PubParams.group, SigParams->dsra, dsra_p, ctx))
    {
        SM9err(SM9_F_SM9_GENERATE_MASTER_SECRET, ERR_R_BN_LIB);
        return 0;
    }
    //printf("Reconverting: %s\n", EC_POINT_point2hex(PubParams.group, dsa_p, POINT_CONVERSION_UNCOMPRESSED, ctx));

    //g = e(P1, Prj), w = g ^ r1
    if(!rate_pairing(w0, &Prj, EC_GROUP_get0_generator(PubParams.group), ctx) || !fp12_pow(w0, w0, r1, PubParams.p, ctx) || !fp12_to_bin(w0, buf0))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_PAIRING_ERROR);
        return 0;
    }
    // h = H2(M||buf0, N)
    if(!SM9_hash2(PubParams.md, &h, msg, strlen(msg), buf0, PubParams.n, ctx) || !BN_mod_sub(sub, r1, h, PubParams.n, ctx))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_DIGEST_FAILURE);
        return 0;

    }
    print_bn("h", h);
    print_bn("r1-h", sub);
    // r2_inv = (r2)^-1 (r1 - h) mod N
    if(!BN_mod_inverse(r2_inv, r2, PubParams.n, ctx) || !BN_mod_mul(r2_inv, r2_inv, sub, PubParams.n, ctx))
    {
        return 0;
    }
    // S1 = (r2_inv)dsa, S2 = (r2_inv)dsra
    if(!EC_POINT_mul(PubParams.group, S1, NULL, dsa_p, r2_inv, ctx) || !EC_POINT_mul(PubParams.group, S2, NULL, dsra_p, r2_inv, ctx))
    {
        SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_SM9_LIB);
        return 0;
    }

    //h2 = H1(IdA || hid, N)
    if (!SM9_hash1(PubParams.md, &h2, idA, strlen(idA), PubParams.hid, PubParams.n, ctx))
    {
        SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_SM9_LIB);
        return 0;
    }
    //P3 = r2([h2]P2 + Ppubs)
    if(!point_mul_generator(&P2, r2, PubParams.p, ctx) || !point_add(&P3, &P2, &Ppubs, PubParams.p, ctx))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_INVALID_POINTPPUB);
        return 0;
    }
    if(!point_mul(&P3, r2, &P3, PubParams.p, ctx))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_INVALID_POINTPPUB);
        return 0;
    }

    // wrap the point
    if(!(ModSignature->h = BN_bn2hex(h))
        || !(ModSignature->S1 = EC_POINT_point2hex(PubParams.group, S1, POINT_CONVERSION_UNCOMPRESSED, ctx))
        || !(ModSignature->S2 = EC_POINT_point2hex(PubParams.group, S2, POINT_CONVERSION_UNCOMPRESSED, ctx))
        || !point_to_octets(&P3, buf0, ctx)
        || !(ModSignature->Prj_hex = SigParams->Prj_hex))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, ERR_R_EC_LIB);
        return 0;
    }
    ModSignature->P3_hex = buf0;
    ModSignature->Ppubs_hex = SigParams->Pubs_hex;
    if(ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if(h && h2)
    {
        BN_free(h);
        BN_free(h2);
    }
    if(r1 && r2)
    {
        BN_free(r1);
        BN_free(r2);
    }
    if(dsa_p && dsra_p && S1 && S2)
    {
        EC_POINT_free(dsa_p);
        EC_POINT_free(dsra_p);
        EC_POINT_free(S1);
        EC_POINT_free(S2);
    }
    if(sub)
    {
        BN_free(sub);
    }
    if(r2_inv)
    {
        BN_free(r2_inv);
    }

    //char *dsa
    return 1;
}



/*void A::SM9Sign(SM9PrivateKey *sk, unsigned char* signature, size_t* len)
{
    unsigned char sig[256] = {0};
    size_t siglen  = 0;
    unsigned char msg[] = "Chinese IBSdsa Standard";
    size_t msglen = strlen((const char*)msg);
    if (!SM9_sign(NID_sm3, msg, msglen, sig, &siglen, sk))
    {
        ERR_print_errors_fp(stderr);
    }
    *len = siglen;
    for(int i = 0;i<siglen;i++)
        signature[i] = sig[i];
    print_hex("Sig Inside Sign", signature, siglen);
}*/

int A::SM9SendSig(struct SM9_MOD_SIG_T sig)
{
    SM9ModSignature* SM9Msg = new SM9ModSignature("SM9 Signature");
    struct SM9_SIG_WRAP_T signature;
    signature.SM9Signature = sig;
    signature.msg = msg;
    SM9Msg->setSM9Signature(signature);

    if(!sendSIG(SM9Msg))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    return 1;
}

int A::sendSIG(SM9ModSignature *SM9Msg)
{

    EV << "A: Sending the SM9 signature to B...\n";
    forwardMessage(SM9Msg);
    return 0;
}

int A::SM9SendResponse(SM9ModSignature *SM9Msg)
{
    EV << "A: Sending the SM9 response to B...\n";
    forwardMessage(SM9Msg);
    return 0;
}

void A::forwardMessage(SM9ModSignature *SM9Msg)
{
    send(SM9Msg,"out"); //the gate "out"
}

A::~A()
{
    EC_GROUP_clear_free(PubParams.group);
    if(SigParams.dsa)
    {
        free(SigParams.dsa);
    }
    if(SigParams.dsra)
    {
        free(SigParams.dsra);
    }
    if(SigParams.Prj_hex)
    {
        free(SigParams.Prj_hex);
    }
    if(SigParams.Pubs_hex)
    {
        free(SigParams.Pubs_hex);
    }


}



void B::initialize(void)
{

}

void B::handleMessage(cMessage* sm9SignMsg)
{
    SM9ModSignature *SM9SignMsg = check_and_cast<SM9ModSignature *>(sm9SignMsg);
    if(strcmp(SM9SignMsg->getName(), "SM9 Signature") == 0)
    {
        int isValid = SM9ModVerify(SM9SignMsg);
        SM9ModSignature *SM9VerMsg = new SM9ModSignature("SM9 Verifying");
        SM9VerMsg->setFlag(isValid);
        /*if(!SM9sendVerify(SM9VerMsg))
        {
            ERR_print_errors_fp(stderr);
        }*/

    }
    else if(strcmp(SM9SignMsg->getName(), "SM9 Response") == 0)
    {
        printf("End of SM9 Signature\n");
    }
    delete SM9SignMsg;
}

int B::SM9ModVerify(SM9ModSignature *SM9SignMsg)
{
    // h1 = H1(SID || hid, N)
    BIGNUM *h1 = NULL, *_h = NULL, *_h2;
    point_t P2, P, _P3, Prj, Ppubs;
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT *_S1, *_S2;
    fp12_t u1, u2, u3, t;
    unsigned char buf1[384], buf2[384], buf3[384];

    ModSignature = SM9SignMsg->getSM9Signature().SM9Signature;


    BN_CTX_start(ctx);
    if(!point_init(&P2, ctx) || !point_init(&P, ctx) || !point_init(&_P3, ctx) || !point_init(&Prj, ctx) || !point_init(&Ppubs, ctx))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if(!fp12_init(u1, ctx) || !fp12_init(u2, ctx) || !fp12_init(u3, ctx) || !fp12_init(t, ctx))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if(!BN_hex2bn(&_h, ModSignature.h)
        ||!point_from_octets(&_P3, ModSignature.P3_hex, PubParams.p, ctx)
        ||!point_from_octets(&Prj, ModSignature.Prj_hex, PubParams.p, ctx)
        ||!point_from_octets(&Ppubs, ModSignature.Ppubs_hex, PubParams.p, ctx)
        ||!EC_POINT_hex2point(PubParams.group, ModSignature.S1, _S1, ctx)
        ||!EC_POINT_hex2point(PubParams.group, ModSignature.S2, _S2, ctx))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (!SM9_hash1(PubParams.md, &h1, PubParams.sid, strlen(PubParams.sid), PubParams.hid, PubParams.n, ctx))
    {
        SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_SM9_LIB);
        return 0;
    }
    if(!point_mul_generator(&P2, h1, PubParams.p, ctx) || !point_add(&P, &P2, &Ppubs, PubParams.p, ctx))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_INVALID_POINTPPUB);
        return 0;
    }
    if(!rate_pairing(u1, &P, _S2, ctx) || !fp12_to_bin(u1, buf1)
        || !rate_pairing(u2, &Prj, _S1, ctx) || !fp12_to_bin(u2, buf2))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_PAIRING_ERROR);
        return 0;
    }


    // compare

    if(!rate_pairing(u3, &_P3, _S1, ctx) || !rate_pairing(t, &Prj, EC_GROUP_get0_generator(PubParams.group), ctx)
        || !fp12_pow(t, t, _h, PubParams.p, ctx)|| !fp12_mul(u3, u3, t, PubParams.p, ctx)
        || !fp12_to_bin(u3, buf3))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_PAIRING_ERROR);
        return 0;
    }
    //compare
    if(!SM9_hash2(PubParams.md, &_h2, msg, strlen(msg), buf3, PubParams.n, ctx))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_DIGEST_FAILURE);
        return 0;
    }
    // compare


    if(h1)
    {
        BN_free(h1);
    }
    if(ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return 1;
}

/*int B::SM9Verify(SM9ModSignature *SM9SignMsg)
{

    unsigned char msg[] = "Chinese IBSdsa Standard";
    size_t msglen = strlen((const char*)msg);
    //struct SM9Sig_t SM9Struct = SM9SignMsg->getSM9SigStruct();
    //int ret = SM9_verify(NID_sm3, msg, msglen, SM9Struct.sig, SM9Struct.siglen, SM9SignMsg->getMpk(), idA, strlen(idA));
    //printf("Verifing Result: %d\n", ret);
    return 1;
}*/

/*int B::SM9sendVerify(SM9ModSignature *SM9Msg)
{
    EV << "B: Sending the SM9 Verifing to A...\n";
    forwardMessage(SM9Msg);
    return 0;
}*/

void B::forwardMessage(SM9ModSignature *SM9Msg)
{
    send(SM9Msg, "out");
}

