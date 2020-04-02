/*
 * SM9Register.cc
 *
 *  Created on: Mar 17, 2020
 *      Author: veins
 */

#include "SM9Reg_util.h"
#include "SM9Register_m.h"
#include "SM9Register.h"


Define_Module(A);
Define_Module(B);

void A::initialize(void)
{
    ks = generate_random_number();
    krj = generate_random_number();
    printf("Here1\n");
}

void A::handleMessage(cMessage *msg)
{
    if(msg->isSelfMessage())
    {
        char MsgName[strlen(msg->getName())];
        strcpy(MsgName, msg->getName());
        delete msg; // cancel first

        if(strcmp(MsgName, "VRC Registered") == 0)
        {
            SM9RegisterMsg* pre_resp = new SM9RegisterMsg("SM9_REG_VRC_RP");
            pre_resp->setPreRegister(RegStruct);
            if(!SM9MsgSend(pre_resp))
            {
                ERR_print_errors_fp(stderr);
                return;
            }
        }
        else if(strcmp(MsgName, "RSU Registering") == 0)
        {
            printf("LOG: In %s-%d\n", __FUNCTION__, __LINE__);
            if(!SetAndSend_RLP(RSUStruct))
            {
                ERR_print_errors_fp(stderr);
                return;
            }
            else
            {
                SM9RegisterMsg* key_gen = new SM9RegisterMsg("RSU KeyGenerating");
                scheduleAt(simTime(), key_gen);
            }

        }
        else if(strcmp(MsgName, "RSU KeyGenerating") == 0)
        {
            printf("Calculating the Region Key\n");
            char *dsa = NULL, *dsra = NULL;
            if(!Calc_PrivateKey(&dsa, &dsra, krj, ks, idA, PubParams))
            {
                ERR_print_errors_fp(stderr);
                return;
            }
            printf("dsa: %s\n", dsa); // need to be freed
            printf("dsra: %s\n", dsra);
            if(!SetAndSend_Key(Kra, dsa, dsra))
            {
                ERR_print_errors_fp(stderr);
                return;
            }
        }
    }
    else
    {
        if(strcmp(msg->getName(), "SM9_REG_REAL_ID") == 0)
        {
            printf("Here2\n");
            SM9RegisterMsg *id_msg = check_and_cast<SM9RegisterMsg *>(msg);
            SM9RegisterMsg *reg_msg = new SM9RegisterMsg("VRC Registered");
            if(!VRC_Register(id_msg))
            {
                RegStruct.flag = 0;
                ERR_print_errors_fp(stderr);
                return;
            }
            delete id_msg; // we should cancel the last event before scheduling the next;
            scheduleAt(simTime(), reg_msg);
        }
        else if(strcmp(msg->getName(), "SM9_REG_IN_RSU") == 0)
        {
            SM9RegisterMsg *car_msg = check_and_cast<SM9RegisterMsg *>(msg);
            RSUStruct = car_msg->getRegionRegister();
            if(!RSU_Setup(&Prj, &PubParams.Ppubs))
            {
                ERR_print_errors_fp(stderr);
                return;
            }
            delete car_msg;
            if(0)//!Is_Authenticated_Car(RSUStruct))
            {
                // this car is fake
                RSUReport(1,"SM9_REG_NO_AUTH", NULL, 0);
                return;
            }
            else
            {
                idA = "X-Alice-CL8038-13123459876";
                SM9RegisterMsg *reg_msg = new SM9RegisterMsg("RSU Registering");
                scheduleAt(simTime(), reg_msg);
            }
        }
        else if(strcmp(msg->getName(), "SM9_REG_CAR_AUTHED") == 0) // check the response
        {
            printf("RSU:End of the registration\n");
            delete msg;
        }

    }

}

int A::VRC_Register(SM9RegisterMsg *id_msg)
{
    struct SM9_VRC_REG_T vrc_reg = id_msg->getPreRegister();
    const char *userid = vrc_reg.id;
    BIGNUM *TA = NULL;
    if(!(TA = pre_register(userid)))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    print_bn("TA", TA);
    RegStruct.Ta = TA;
    RegStruct.RLP = VEHICLE_INIT;
    return 1;
}

int A::RSU_Setup(unsigned char **point_buf, unsigned char **Ppub_buf)
{
    printf("LOG: In %s-%d\n", __FUNCTION__, __LINE__);
    point_t P2, Ppubs;
    unsigned char *buf = (unsigned char*)malloc(sizeof(char) * 130);
    unsigned char *buf2 = (unsigned char*)malloc(sizeof(char) * 130);
    //unsigned char buf[129], buf2[129];
    BN_CTX *ctx = BN_CTX_new();
    memset(buf, 0, sizeof(char)*130);
    memset(buf2, 0, sizeof(char)*130);

    BN_CTX_start(ctx);
    if(!point_init(&P2, ctx) || !point_mul_generator(&P2, krj, SM9_get0_prime(), ctx) || !point_to_octets(&P2, buf, ctx))
    {
        SM9err(SM9_F_SM9_GENERATE_MASTER_SECRET, SM9_R_TWIST_CURVE_ERROR);
        return 0;
    }
    *point_buf = buf;
    if(!point_init(&Ppubs, ctx) || !point_mul_generator(&Ppubs, ks, SM9_get0_prime(), ctx) || !point_to_octets(&Ppubs, buf2, ctx))
    {
        SM9err(SM9_F_SM9_GENERATE_MASTER_SECRET, SM9_R_TWIST_CURVE_ERROR);
        return 0;
    }
    *Ppub_buf = buf2;
    if(ctx)
    {
        BN_CTX_end(ctx);
    }
    BN_CTX_free(ctx);
    return 1;
}

BIGNUM* A::pre_register(const char* id)
{
    BIGNUM *TA=BN_new(), *t2 = NULL;
    BN_CTX *ctx = BN_CTX_new();
    size_t idlen = strlen(id);
    fp12_t w0;
    unsigned char buf0[384];
    EC_POINT *P1 = EC_POINT_new(PubParams.group);
    point_t Pr2, Ppubs;
    const EVP_MD *md2 = EVP_get_digestbynid(NID_sm3);
    EVP_MD_CTX *ctx2 = EVP_MD_CTX_new();
    unsigned int hlen = 0;

    if (idlen <= 0 || idlen > SM9_MAX_ID_LENGTH)
    {
        SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, SM9_R_INVALID_ID);
        return NULL;
    }
    if (!ks)
    {
        SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, SM9_R_NO_MASTER_SECRET);
        return NULL;
    }

    BN_CTX_start(ctx);
    // generate the TA
    if (!SM9_hash1(PubParams.md, &t2, id, idlen, PubParams.hid, PubParams.n, ctx))
    {
        SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_SM9_LIB);
        return NULL;
    }
    if(!BN_mod_mul(TA, ks, t2, PubParams.n, ctx)) // calculate the number before the P1 first
    {
        SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_RATE_PAIRING_ERROR);
        return NULL;
    }

    // generate the identity tuple (buf0, id)
    if(!fp12_init(w0, ctx) || !point_init(&Pr2, ctx))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_PAIRING_ERROR);
        return NULL;
    }
    if(!EC_POINT_mul(PubParams.group, P1, ks, NULL, NULL, ctx) || !point_mul_generator(&Pr2, t2, PubParams.p, ctx))
    {
        SM9err(SM9_F_SM9_MASTER_KEY_EXTRACT_KEY, ERR_R_SM9_LIB);
        EC_POINT_free(P1);
    }
    if(!rate_pairing(w0, &Pr2, P1, ctx) || !fp12_to_bin(w0, buf0)) // w = e(ksP1, t2P2)
    {
        SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_PAIRING_ERROR);
    }
    if (!EVP_DigestInit_ex(ctx2, md2, NULL) ||!EVP_DigestUpdate(ctx2, PubParams.sid, sizeof(PubParams.sid))
            ||!EVP_DigestUpdate(ctx2, buf0, sizeof(buf0)) || !EVP_DigestFinal_ex(ctx2, buf0, &hlen))
    {
        SM9err(SM9_F_SM9_SIGNINIT, ERR_R_EVP_LIB);
        return 0;
    }
    //store the identity tuple
    if(!identity_write(buf0, hlen, id) || !RLitem_write(t2, id))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    printf("Here5\n");

    BN_CTX_end(ctx);
    if(ctx)
    {
        BN_CTX_free(ctx);
    }
    if(ctx2)
    {
        EVP_MD_CTX_free(ctx2);
    }
    EC_POINT_free(P1);
    if(t2)
    {
        BN_free(t2);
    }

    return TA;

}

int A::Is_Authenticated_Car(struct SM9_RSU_REG_T rsu_reg)
{
    printf("In Is_Authenticated_Car\n");
    if(!rsu_reg.Ta)
    {
        return 0;
    }
    BIGNUM* Tcar = rsu_reg.Ta;
    if(!Check_Revoked(Tcar))
    {
        printf("This car has to be revoked.\n");
        // this car need to be revoked
        RSUReport(1,"SM9_REG_FAILED", NULL, 0);
        return 0;
    }
    if(!Check_Authenticated(Tcar))
    {
        RSUReport(0,"SM9_REG_FAILED", NULL, 0);
        // this car is fake
        printf("This car is not authenticated.\n");
        // maybe RSU can silently record this car's information
        return 0;
    }
    return 1;
}


int A::Check_Authenticated(BIGNUM* Tcar)
{
    printf("In Check_Authenticated\n");
    point_t Pt2;
    fp12_t w1;
    BN_CTX *ctx = BN_CTX_new();
    const EVP_MD *md2 = EVP_get_digestbynid(NID_sm3);
    EVP_MD_CTX *ctx2 = EVP_MD_CTX_new();
    unsigned int hlen = 0;
    unsigned char buf1[384];
    BN_CTX_start(ctx);
    if(!point_init(&Pt2, ctx) || !fp12_init(w1, ctx))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if(!point_mul_generator(&Pt2, Tcar, PubParams.p, ctx) || !rate_pairing(w1, &Pt2, EC_GROUP_get0_generator(PubParams.group), ctx) || !fp12_to_bin(w1, buf1))
    {
        SM9err(SM9_F_SM9_SIGNFINAL, SM9_R_EXTENSION_FIELD_ERROR);
        return 0;
    }
    if (!EVP_DigestInit_ex(ctx2, md2, NULL) ||!EVP_DigestUpdate(ctx2, PubParams.sid, sizeof(PubParams.sid))
                ||!EVP_DigestUpdate(ctx2, buf1, sizeof(buf1)) || !EVP_DigestFinal_ex(ctx2, buf1, &hlen))
    {
        SM9err(SM9_F_SM9_SIGNINIT, ERR_R_EVP_LIB);
        return 0;
    }
    // w1 = e(P1, TAP2) = e(ksP1, t2P2)
    // buf1 = H(sid || bin(w1))
    if(!(idA = Search_Identity(buf1, hlen)) || idA == NULL)
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    printf("IDA:%s\n", idA);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EVP_MD_CTX_free(ctx2);
    return 1;
}


int A::identity_write(unsigned char* buf, unsigned int len, const char* id)
{
    FILE *fp = fopen("identity_tuple.txt", "a+");
    if (!fp)
    {
        fprintf(stderr, "Error opening file : %s.\n",strerror(errno));
        return 0;
    }
    if(!hex_write(fp, buf, len, id))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    return 1;
}

int A::RLitem_write(BIGNUM* t2, const char* id)
{
    FILE *fp = fopen("RL.txt", "a+");
    if (!fp)
    {
        fprintf(stderr, "Error opening file : %s.\n",strerror(errno));
        return 0;
    }
    if(bn_write(fp, id, t2))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    return 1;
}

int A::Check_Revoked(BIGNUM *Tcar)
{
    // get the RL file
    // do the pairing operation
    // searching the RL
    // return the result
    return 1;
}

int A::SetAndSend_RLP(struct SM9_RSU_REG_T RSUStruct)
{
    //search the rsu params and check rlp
    double distance = Calc_Last_Distance(RSUStruct);
    unsigned char *new_RLP = NULL;
    unsigned char *cyphertxt;
    if(distance <= threshold) // no need to update the RLP and KEY
    {
        new_RLP = RSUStruct.RLP;
    }
    else
    {
        Calc_New_RLP(RSUStruct, &new_RLP); // far away from the last RSU
    }
    if(!new_RLP || !Enc_RLP(new_RLP, krj, idA, PubParams, &cyphertxt, &Kra) || !cyphertxt)
    {
        return 0;
    }
    //print_hex("cyphertxt", cyphertxt, 64);
    RSUReport(0,"SM9_REG_AUTH_RSU", cyphertxt, HASH_LENGTH);
    return 1;
}


int A::SetAndSend_Key(unsigned char *Kra, char *dsa, char *dsra)
{
    char private_key[256];
    unsigned char *cyphertxt = NULL;
    memcpy(private_key, dsa + 2, sizeof(char) * 128);
    memcpy(private_key + 128, dsra + 2, sizeof(char) * 128);

    if(!Enc_KEY(private_key, &cyphertxt, Kra, idA) || !cyphertxt)
    {
        return 0;
    }
    //print_hex("KEY:cyphertxt", cyphertxt, 2 * EC_POINT_HEX_LENGTH);
    RSUReport(0, "SM9_REG_REGION_KEY", cyphertxt, 2 * EC_POINT_HEX_LENGTH);
    free(dsa);
    free(dsra);
    return 1;
}

int A::RSUReport(int flag, const char* label, unsigned char *ciphertxt, int len)
{
    printf("RSU: Sending Message\n");
    if(flag)
    {
        printf("RSU: Sending this Car's identity credential to RMA\n");
        return 1;
    }

    struct SM9_RSU_REG_T send_struct;
    SM9RegisterMsg *rsu_msg = new SM9RegisterMsg(label);
    send_struct.point_rj = Prj;
    send_struct.point_pubs = PubParams.Ppubs;
    if(strcmp(label, "SM9_REG_NO_AUTH") == 0 || strcmp(label, "SM9_REG_FAILED") == 0)
    {
        rsu_msg->setFlag(0);
    }
    else if(strcmp(label, "SM9_REG_AUTH_RSU") == 0 || strcmp(label, "SM9_REG_REGION_KEY") == 0)
    {
        rsu_msg->setFlag(1);
        for(int i = 0;i < len;i++)
            send_struct.enc_buf[i] = ciphertxt[i]; // here 12.27
        free(ciphertxt);
    }

    rsu_msg->setRegionRegister(send_struct);
    if(!SM9MsgSend(rsu_msg))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    return 1;
}

int A::SM9MsgSend(SM9RegisterMsg *SM9Msg)
{
    EV << "VRC: Sending the credential to user...\n";
    forwardMessage(SM9Msg);
    return 0;
}

void A::forwardMessage(SM9RegisterMsg *SM9Msg)
{
    send(SM9Msg,"out"); //the gate "out"
}

void A::finish()
{

}

A::~A()
{
    if(ks)
    {
        BN_free(ks);
    }
    if(krj)
    {
        BN_free(krj);
    }
    /*if(idA)
    {
        free((char*)idA);
    }*/
    if(RegStruct.Ta)
    {
        BN_free(RegStruct.Ta);
    }
    EC_GROUP_clear_free(PubParams.group);
    if(Kra)
    {
        free(Kra);
    }
    //free(Kra);
    if(Prj)
    {
        free(Prj);
    }
    if(PubParams.Ppubs)
    {
        free(PubParams.Ppubs);
    }
    //point_cleanup((point_t*)Prj);
}


void B::initialize(void)
{
    TA = BN_new();
    SM9RegisterMsg* pre_reg = NULL;
    if(!(pre_reg = VRCRegSetup()) || !SM9MsgSend(pre_reg))
    {
        ERR_print_errors_fp(stderr);
        return;
    }
    printf("Here3\n");

}

void B::handleMessage(cMessage *msg)
{
    if(msg->isSelfMessage())
    {
        if(strcmp(msg->getName(), "Vehicle Entered Region") == 0)
        {
            delete msg;
            // Entering into the RSU area, send Ta and RLP
            SM9RegisterMsg* rsu_reg_msg = new SM9RegisterMsg("SM9_REG_IN_RSU");
            RSUStruct.RLP = RLP;
            RSUStruct.Ta = TA;
            rsu_reg_msg->setRegionRegister(RSUStruct);
            if(!SM9MsgSend(rsu_reg_msg))
            {
                ERR_print_errors_fp(stderr);
                return;
            }
        }
    }
    else
    {
        if(strcmp(msg->getName(), "SM9_REG_VRC_RP") == 0)
        {
            printf("Here6\n");
            SM9RegisterMsg* resp_msg = check_and_cast<SM9RegisterMsg *>(msg);
            SM9RegisterMsg* enter_msg = new SM9RegisterMsg("Vehicle Entered Region");
            BN_copy(TA, resp_msg->getPreRegister().Ta); // store a copy for convenience
            print_bn("TA", TA);
            delete resp_msg;
            scheduleAt(simTime(), enter_msg);
        }
        else if(strcmp(msg->getName(), "SM9_REG_FAILED") == 0) // not authenticated car
        {
            //end
            //SM9_REG_NO_AUTH
            delete msg;
            printf("End of the Scheme.\n");
            finish();
        }
        else if(strcmp(msg->getName(), "SM9_REG_AUTH_RSU") == 0) // get enc and wait for key
        {
            // getPrj
            printf("LOG: In %s-%d\n", __FUNCTION__, __LINE__);
            SM9RegisterMsg* resp_msg = check_and_cast<SM9RegisterMsg *>(msg);
            struct SM9_RSU_REG_T t = resp_msg->getRegionRegister();
            Prj = t.point_rj;
            PubParams.Ppubs = t.point_pubs;
            if(!isAuthenticatedRSU(t))
            {
                printf("Not an trusted RSU\n");
            }
            else
            {
                printf("it is an trusted RSU\n");
            }
            delete resp_msg;

        }
        else if(strcmp(msg->getName(), "SM9_REG_REGION_KEY") == 0) // get key enc and dec get key
        {
            printf("LOG: In %s-%d Decrpyting Keys \n", __FUNCTION__, __LINE__);
            SM9RegisterMsg* resp_msg = check_and_cast<SM9RegisterMsg *>(msg);
            struct SM9_RSU_REG_T t = resp_msg->getRegionRegister();
            print_hex("B:Key cyphertxt", t.enc_buf, 2 * EC_POINT_HEX_LENGTH);
            if(!Dec_Key(t, Kra, id, &dsa, &dsra) || !dsa || !dsra)
            {
                ERR_print_errors_fp(stderr);
                return;
            }
            delete resp_msg;
            if(!SendResponse(1) || !Key_write(id, dsa, dsra, Prj, PubParams.Ppubs))
            {
                ERR_print_errors_fp(stderr);
                return;
            }
        }

    }
}

SM9RegisterMsg* B::VRCRegSetup()
{
    SM9RegisterMsg* pre_reg = new SM9RegisterMsg("SM9_REG_REAL_ID");
    struct SM9_VRC_REG_T vrc_reg;
    vrc_reg.id = id;
    pre_reg->setPreRegister(vrc_reg);
    return pre_reg;
}

int B::isAuthenticatedRSU(struct SM9_RSU_REG_T t)
{
    //unsigned char* key;
    print_hex("B:cyphertxt", t.enc_buf, HASH_LENGTH);
    if(!Calc_Enc_Key(t.point_rj, PubParams, id, &Kra) || !Check_Cypher(Kra, id, t.enc_buf, &RLP))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    return 1;
}

int B::Key_write(const char* id, char *memberKey, char *regionKey, unsigned char *point_rj, unsigned char *point_pubs)
{
    //char filename[100] = "/home/VANETSIM/SM9REG/";
    printf("IN write key: %s\n%s\n", memberKey, regionKey);
    const char *path = "/home/veins/VANETSIM/SM9REG/";
    const char *type = ".txt";
    int len = strlen(path) + strlen(id) + strlen(type) + 1;
    char filename[len];
    memset(filename, 0, len);
    strcpy(filename, path);
    strcat(filename, id);
    strcat(filename, type); // ok here
    printf("filename: %s\n", filename);

    FILE *fp = fopen(filename, "wb"); // ok here
    if(!fp)
    {
        fprintf(stderr, "Error opening file '%s': %s.\n",
                        filename, strerror(errno));
        return 0;
    }
    if(memberKey && regionKey)
    {
        fprintf(fp, "%s\n", memberKey);
        fprintf(fp, "%s\n", regionKey);
    }
    else
    {
        return 0;
    }

    if(point_rj && point_pubs)
    {
        for(int i = 0;i < 129;i++)
            fprintf(fp, "%02x", point_rj[i]);
        fprintf(fp, "\n");
        for(int i = 0;i < 129;i++)
             fprintf(fp, "%02x", point_pubs[i]);
        fprintf(fp, "\n");
        //fprintf(fp, "%s\n", point_pubs);
    }
    fclose(fp);
    return 1;
}


int B::SendResponse(int flag)
{
    SM9RegisterMsg* resp_reg = new SM9RegisterMsg("SM9_REG_CAR_AUTHED");
    resp_reg->setFlag(1);
    if(!SM9MsgSend(resp_reg))
    {
        return 0;
    }
    return 1;
}

int B::SM9MsgSend(SM9RegisterMsg *SM9Msg)
{
    EV << "User: Sending the real ID to VRC...\n";
    forwardMessage(SM9Msg);
    return 1;
}

void B::forwardMessage(SM9RegisterMsg *SM9Msg)
{
    send(SM9Msg,"out"); //the gate "out"
}

B::~B()
{
    if(TA)
    {
        BN_free(TA);
    }
    EC_GROUP_clear_free(PubParams.group);
    if(RLP)
    {
        free(RLP);
    }// it's ok here 2020.3.26.11.25
    if(Kra)
    {
        free(Kra);
    }
    if(dsa)
    {
        free(dsa);
    }
    if(dsra)
    {
        free(dsra);
    }
}
