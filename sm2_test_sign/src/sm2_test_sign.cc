/*
 * sm2_test_sign.cc
 *
 *  Created on: Dec 27, 2019
 *      Author: veins
 */

#include "sign_util.h"
#include "sm2Sign_m.h"
#include <ctime>

using namespace omnetpp;


class A: public cSimpleModule
{
    private:
        ECDSA_SIG* sign(unsigned char *mhash);
        int sendSIG(sm2signMsg_t *sm2signMsg);
        int getStat(sm2signMsg_t *sm2signMsg);
        int sendResponse(sm2signMsg_t *sm2signMsg);
        void forwardMessage(sm2signMsg_t *sm2signMsg);

    protected:
        virtual void initialize() override;
        virtual void handleMessage(cMessage *sm2signMsg) override ;

    public:
        sm2signMsg_t *sm2signMsg;
        EC_KEY *eckey;
        ECDSA_SIG *signature;
};


class B : public cSimpleModule
{
    private:
        int verifySIG(sm2signMsg_t *sm2signMsg);
        void forwardMessage(sm2signMsg_t *sm2signMsg);
        void handleResponse(sm2signMsg_t *sm2signMsg);

    protected:
        virtual void initialize() override;
        virtual void handleMessage(cMessage *sm2signMsg) override;

    public:
        sm2signMsg_t *sm2signMsg;
        EC_KEY *eckey;
        ECDSA_SIG *signature;
};

Define_Module(A);
Define_Module(B);

void A::initialize()
{
    EV <<"A: initializing ECDSA......\n";
    const BIGNUM *sig_r;
    const BIGNUM *sig_s;
    unsigned char* dgst;
    sm2signMsg_t *sm2signMsg = new sm2signMsg_t("signature");
    if(!(A::eckey = read_key()))
    {
        return;
    }
    A::eckey = get_new_key();
    sm2_key_write(A::eckey);
    sm2_log_key("key of A", A::eckey);
    dgst = get_digest(A::eckey, "zxl@YAHOO.COM", "message digest");

    //printf("A side, get dgst: ");
    //print_hex(dgst, 32);
    A::signature = sign(dgst);
    ECDSA_SIG_get0(A::signature, &sig_r, &sig_s);

    //print_bignum('r', sig_r);
    //print_bignum('s', sig_s);

    sm2signMsg->setSigR(sig_r);
    sm2signMsg->setSigS(sig_s);
    sm2signMsg->setDgst(dgst);

    A::sm2signMsg = sm2signMsg;
    if(sendSIG(A::sm2signMsg) == -1)
    {
        EV << "A: send signature failed..\n";
        exit(0);
    }
}

void A::handleMessage(cMessage *sm2signMsg)
{
    sm2signMsg_t *msg = check_and_cast<sm2signMsg_t *>(sm2signMsg);
    if(getStat(msg) != -1)
    {
        ECDSA_SIG_free(A::signature);
        delete sm2signMsg;
    }
    else
    {
        EV << "A: Something Wrong...\n";
        exit(-1);
    }
}

ECDSA_SIG* A::sign(unsigned char* dgst)
{
    EV << "A: Signing the message using ECDSA...\n";
    int function_status = -1;
    unsigned int siglen;
    static unsigned char sig[256];
    const unsigned char *p;

    int type = NID_undef;
    ECDSA_SIG *sm2_sig = NULL;
    //EC_KEY* pub_key = get_new_pub_key();

    if (NULL == A::eckey)
    {
        EV << "Failed to create new EC Key\n";
        function_status = -1;
    }
    else
    {
        siglen = sizeof(sig);
        //printf("A side: Signing: ");
        //print_hex(dgst, 32);
        if (!SM2_sign(type, dgst, 32, sig, &siglen, A::eckey))
        {
            fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
        }
        //printf("A side: Signature ");
        //print_hex(sig, 128);
        printf("siglen: %d\n", siglen);
        p = sig;
        if (!(sm2_sig = d2i_ECDSA_SIG(NULL, &p, siglen)))
        {
            fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
        }

        //int verify_status = SM2_verify(type, dgst, 32, sig, siglen, pub_key);
        //printf("A verify_status: %d\n",verify_status);

        if (NULL == sm2_sig)
        {
            EV << "Failed to generate EC Signature\n";
            function_status = -1;
        }
        else
        {
            function_status = 1;
        }
    }

    if(function_status == -1)
    {
        exit(-1);
    }
    return sm2_sig;
}

int A::sendSIG(sm2signMsg_t *sm2signMsg)
{

    EV << "A: Sending the signature to B...\n";
    forwardMessage(sm2signMsg);
    return 0;
}

int A::getStat(sm2signMsg_t *sm2signMsg)
{
    sm2signMsg_t *msg = new sm2signMsg_t("response");
    msg->setReceived(1);

    if(sm2signMsg->getFlag() == 1)
    {
        EV <<"A: Valid Signature\n";
        //printf("Valid!!!!\n");
    }
    else
        EV << "A : something wrong.\n";
    A::sm2signMsg = msg;
    if(sendResponse(A::sm2signMsg) == -1)
    {
        exit(-1);
    }
    return 0;
}

int A::sendResponse(sm2signMsg_t *sm2signMsg)
{
    forwardMessage(sm2signMsg);
    EC_KEY_free(A::eckey);
    return 0;
}

void A::forwardMessage(sm2signMsg_t *sm2signMsg)
{
    send(sm2signMsg,"out");
}







void B::initialize()
{
    //B::eckey = read_key();
    B::eckey = get_new_pub_key();
}

void B::handleMessage(cMessage *sm2signMsg)
{
    sm2signMsg_t *msg = check_and_cast<sm2signMsg_t *>(sm2signMsg);
    if(strcmp(sm2signMsg->getName(),"signature") == 0)
    {
        EV << "B: Receiving the signature from A...\n";
        if(verifySIG(msg) == -1)
        {
            EV <<"Something Wrong during verifying...\n";
        }

    }
    else if(strcmp(sm2signMsg->getName(),"response") == 0)
    {
        EV << "B: Receiving the confirm message from A...\n";
        handleResponse(msg);
        delete sm2signMsg;
    }
}


int B::verifySIG(sm2signMsg_t *sm2signMsg)
{
    unsigned char sig[256];
    unsigned char* p = sig;
    int type = NID_undef;
    ECDSA_SIG *sm2_sig = ECDSA_SIG_new();
    const BIGNUM* sigr = sm2signMsg->getSigR();
    const BIGNUM* sigs = sm2signMsg->getSigS();
    unsigned char* h = sm2signMsg->getDgst();


    if(B::eckey == NULL)
    {
        return -1;
    }

    clock_t time1 = clock();
    ECDSA_SIG_set0(sm2_sig, (BIGNUM*)sigr, (BIGNUM*)sigs);
    if(!i2d_ECDSA_SIG(sm2_sig, &p))
    {
        EV <<"Something wrong..."<<endl;
    }
    unsigned int siglen = sizeof(sig);
    // B::eckey = get_new_pub_key();
    const int verify_status = SM2_verify(type, h, 32, sig, 70, B::eckey);
    clock_t time2 = clock();
    printf("verify time: %lf\n", ((double)(time2 - time1))/CLOCKS_PER_SEC);
    EV << "Result: " << verify_status << endl;
    printf("Result: %d\n", verify_status);

    const int verify_success = 1;
    if (verify_success != verify_status)
    {
        EV <<"B: Failed to verify EC Signature\n";
        return -1;
    }
    else
    {

        EV <<"B: Verifed EC Signature\n";
        sm2signMsg->setFlag(1);
    }
    B::sm2signMsg = sm2signMsg;
    forwardMessage(B::sm2signMsg);
    return 0;
}

void B::handleResponse(sm2signMsg_t *sm2signMsg)
{
    if(sm2signMsg->getReceived() == 1)
    {
        EV << "OK...\n";
        //printf("OK motherfucker\n");
    }
    else
    {
        //printf("wrong motherfucker\n");
        EV << "Wrong..\n";
    }
    EC_KEY_free(B::eckey);
    //B::signature = NULL;
    //ECDSA_SIG_free(B::signature);
}


void B::forwardMessage(sm2signMsg_t *sm2signMsg)
{
    send(sm2signMsg,"out");
}
