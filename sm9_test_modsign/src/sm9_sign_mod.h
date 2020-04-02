/*
 * sm9_sign_mod.h
 *
 *  Created on: Mar 30, 2020
 *      Author: veins
 */

#ifndef SM9_SIGN_MOD_H_
#define SM9_SIGN_MOD_H_

using namespace omnetpp;

class A: public cSimpleModule
{
    private:
        int SM9_ModSign_Setup(struct SM9_SIG_PARAM_T *SigParams);
        //SM9PrivateKey* generatePrivateKey(SM9PublicParameters *mpk, SM9MasterSecret *msk);
        int SM9_ModSign(struct SM9_SIG_PARAM_T *SigParams, struct SM9_MOD_SIG_T *ModSignature);

        int SM9SendSig(struct SM9_MOD_SIG_T sig);
        //void SM9Sign(SM9PrivateKey *sk, unsigned char* signature, size_t* len);

        int sendSIG(SM9ModSignature *SM9Msg);
        int SM9SendResponse(SM9ModSignature *SM9Msg);
        void forwardMessage(SM9ModSignature *SM9Msg);
        virtual ~A() override;


    protected:
        virtual void initialize() override;
        virtual void handleMessage(cMessage *sm9signMsg) override ;


    public:
        struct SM9_SIG_PARAM_T SigParams;
        struct SM9_MOD_SIG_T ModSignature;
        struct SM9_PUB_PARAM_T PubParams;

        char *dsa;
        char *dsra;
        unsigned char Prj_hex[POINT_T_SIZE];
        const char *idA = "X-Alice-CL8038-13123459876";
        const char *msg = "Chinese IBSdsa Standard";
        unsigned char sig[256];
        size_t siglen = 0;
        //unsigned char msg[100];

};

class B: public cSimpleModule
{
    private:
        //ECDSA_SIG* sign(unsigned char *mhash);
        //int sendSIG(sm2signMsg_t *sm2signMsg);
        //int getStat(sm2signMsg_t *sm2signMsg);
        //int sendResponse(sm2signMsg_t *sm2signMsg);
        //void forwardMessage(sm2signMsg_t *sm2signMsg);
        //int SM9Verify(SM9_SIGN_MSG_t *SM9SignMsg);
        //int SM9sendVerify(SM9_SIGN_MSG_t *SM9Msg);
        int SM9ModVerify(SM9ModSignature *SM9SignMsg);
        void forwardMessage(SM9ModSignature *SM9Msg);

    protected:
        virtual void initialize(void) override;
        virtual void handleMessage(cMessage *sm9signMsg) override ;

    public:
        const char *idA = "UserA";
        struct SM9_PUB_PARAM_T PubParams;
        struct SM9_MOD_SIG_T ModSignature;
        const char *msg = "Chinese IBSdsa Standard";

};


#endif /* SM9_SIGN_MOD_H_ */
