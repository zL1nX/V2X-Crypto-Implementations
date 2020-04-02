/*
 * SM9Sign.cc
 *
 *  Created on: Mar 16, 2020
 *      Author: veins
 */

#include "SM9Sign_util.h"
#include "SM9Sign_m.h"

using namespace omnetpp;

class A: public cSimpleModule
{
    private:
        SM9PrivateKey* generatePrivateKey(SM9PublicParameters *mpk, SM9MasterSecret *msk);
        int SM9SendSig(unsigned char* sig, size_t siglen);
        void SM9Sign(SM9PrivateKey *sk, unsigned char* signature, size_t* len);
        int sendSIG(SM9_SIGN_MSG_t *SM9Msg);
        int SM9SendResponse(SM9_SIGN_MSG_t *SM9Msg);
        void forwardMessage(SM9_SIGN_MSG_t *SM9Msg);
        //SM9Signature* sign();
        //ECDSA_SIG* sign(unsigned char *mhash);

        //int getStat(sm2signMsg_t *sm2signMsg);
        //int sendResponse(sm2signMsg_t *sm2signMsg);


    protected:
        virtual void initialize() override;
        virtual void handleMessage(cMessage *sm9signMsg) override ;


    public:
        SM9PublicParameters *mpk = NULL;
        SM9MasterSecret *msk = NULL;
        SM9PrivateKey *sk = NULL;
        const char *idA = "UserA";
        unsigned char sig[256];
        size_t siglen = 0;
        unsigned char msg[100];

};

class B: public cSimpleModule
{
    private:
        //ECDSA_SIG* sign(unsigned char *mhash);
        //int sendSIG(sm2signMsg_t *sm2signMsg);
        //int getStat(sm2signMsg_t *sm2signMsg);
        //int sendResponse(sm2signMsg_t *sm2signMsg);
        //void forwardMessage(sm2signMsg_t *sm2signMsg);
        int SM9Verify(SM9_SIGN_MSG_t *SM9SignMsg);
        int SM9sendVerify(SM9_SIGN_MSG_t *SM9Msg);
        void forwardMessage(SM9_SIGN_MSG_t *SM9Msg);

    protected:
        virtual void initialize(void) override;
        virtual void handleMessage(cMessage *sm9signMsg) override ;

    public:
        const char *idA = "UserA";

};
Define_Module(A);
Define_Module(B);

void A::initialize(void)
{
    if(!SM9_setup(NID_sm9bn256v1, NID_sm9sign, NID_sm9hash1_with_sm3, &mpk, &msk))
    {
        ERR_print_errors_fp(stderr);
        return;
    }
    SM9_SIGN_MSG_t *init_reminder = new SM9_SIGN_MSG_t("initialized");
    scheduleAt(simTime(), init_reminder);
}


void A::handleMessage(cMessage *msg)
{
    if(msg->isSelfMessage())
    {
        if(strcmp(msg->getName(), "initialized") == 0)
        {
            sk = generatePrivateKey(mpk, msk);
            print_bn("ks", msk->masterSecret);
            SM9Sign(sk, sig, &siglen);
            print_hex("Sig After Sign", sig, siglen);
            if(siglen)
            {
                SM9_SIGN_MSG_t *sign_reminder = new SM9_SIGN_MSG_t("signed");
                scheduleAt(simTime(), sign_reminder);
            }
        }
        else if(strcmp(msg->getName(), "signed") == 0)
        {
            if(!SM9SendSig(sig, siglen))
            {
                ERR_print_errors_fp(stderr);
            }
        }
        delete msg;
    }
    else
    {
        SM9_SIGN_MSG_t *SM9SignMsg = check_and_cast<SM9_SIGN_MSG_t *>(msg);
        if(strcmp(SM9SignMsg->getName(), "SM9 Verifying") == 0)
        {
            SM9_SIGN_MSG_t *SM9RespMsg = new SM9_SIGN_MSG_t("SM9 Response");
            if(!SM9SendResponse(SM9RespMsg))
            {
                ERR_print_errors_fp(stderr);
            }
            SM9PublicParameters_free(mpk);
            SM9MasterSecret_free(msk);
            SM9PrivateKey_free(sk);
        }
        delete SM9SignMsg;
    }

}

SM9PrivateKey* A::generatePrivateKey(SM9PublicParameters *mpk, SM9MasterSecret *msk)
{
    SM9PrivateKey *ret = NULL;
    if (!(ret = SM9_extract_private_key(msk, idA, strlen(idA))))
    {
        ERR_print_errors_fp(stderr);
    }
    return ret;
}

void A::SM9Sign(SM9PrivateKey *sk, unsigned char* signature, size_t* len)
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
}

int A::SM9SendSig(unsigned char* sig, size_t siglen)
{
    SM9_SIGN_MSG_t* SM9Msg = new SM9_SIGN_MSG_t("SM9 Signature");
    static unsigned char msg[] = "Chinese IBSdsa Standard";
    size_t msglen = strlen((const char*)msg);
    struct SM9Sig_t s;
    for(int i = 0;i<siglen;i++)
        s.sig[i] = sig[i];
    for(int i = 0;i<msglen;i++)
        s.msg[i] = msg[i];
    s.siglen = siglen;
    SM9Msg->setSM9SigStruct(s);
    SM9Msg->setMpk(mpk);

    if(!sendSIG(SM9Msg))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    return 1;
}

int A::sendSIG(SM9_SIGN_MSG_t *SM9Msg)
{

    EV << "A: Sending the SM9 signature to B...\n";
    forwardMessage(SM9Msg);
    return 0;
}

int A::SM9SendResponse(SM9_SIGN_MSG_t *SM9Msg)
{
    EV << "A: Sending the SM9 response to B...\n";
    forwardMessage(SM9Msg);
    return 0;
}

void A::forwardMessage(SM9_SIGN_MSG_t *SM9Msg)
{
    send(SM9Msg,"out"); //the gate "out"
}


void B::initialize(void)
{

}

void B::handleMessage(cMessage* sm9SignMsg)
{
    SM9_SIGN_MSG_t *SM9SignMsg = check_and_cast<SM9_SIGN_MSG_t *>(sm9SignMsg);
    if(strcmp(SM9SignMsg->getName(), "SM9 Signature") == 0)
    {
        int isValid = SM9Verify(SM9SignMsg);
        SM9_SIGN_MSG_t *SM9VerMsg = new SM9_SIGN_MSG_t("SM9 Verifying");
        SM9VerMsg->setFlag(isValid);
        if(!SM9sendVerify(SM9VerMsg))
        {
            ERR_print_errors_fp(stderr);
        }

    }
    else if(strcmp(SM9SignMsg->getName(), "SM9 Response") == 0)
    {
        printf("End of SM9 Signature\n");
    }
    delete SM9SignMsg;
}

int B::SM9Verify(SM9_SIGN_MSG_t *SM9SignMsg)
{

    unsigned char msg[] = "Chinese IBSdsa Standard";
    size_t msglen = strlen((const char*)msg);
    struct SM9Sig_t SM9Struct = SM9SignMsg->getSM9SigStruct();
    int ret = SM9_verify(NID_sm3, msg, msglen, SM9Struct.sig, SM9Struct.siglen, SM9SignMsg->getMpk(), idA, strlen(idA));
    printf("Verifing Result: %d\n", ret);
    return ret;
}

int B::SM9sendVerify(SM9_SIGN_MSG_t *SM9Msg)
{
    EV << "B: Sending the SM9 Verifing to A...\n";
    forwardMessage(SM9Msg);
    return 0;
}

void B::forwardMessage(SM9_SIGN_MSG_t *SM9Msg)
{
    send(SM9Msg, "out");
}



