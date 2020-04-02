/*
 * SM9Register.h
 *
 *  Created on: Mar 17, 2020
 *      Author: veins
 */

#ifndef SM9REGISTER_H_
#define SM9REGISTER_H_

using namespace omnetpp;

class A: public cSimpleModule
{
    private:
        //SM9PrivateKey* generatePrivateKey(SM9PublicParameters *mpk, SM9MasterSecret *msk);
        //int SM9SendSig(unsigned char* sig, size_t siglen);
        //void SM9Sign(SM9PrivateKey *sk, unsigned char* signature, size_t* len);
        int VRC_Register(SM9RegisterMsg *id_msg);
        BIGNUM* pre_register(const char* id);
        int SetAndSend_RLP(struct SM9_RSU_REG_T RSUStruct);
        int SetAndSend_Key(unsigned char *Kra, char *dsa, char *dsra);
        int RSU_Setup(unsigned char **point_buf, unsigned char **Ppub_buf);
        int Is_Authenticated_Car(struct SM9_RSU_REG_T RSUStruct);
        int Check_Revoked(BIGNUM *TA);
        int Check_Authenticated(BIGNUM* TA);
        int identity_write(unsigned char* buf, unsigned int len, const char* id);
        int RLitem_write(BIGNUM *n, const char* id);
        int RSUReport(int flag, const char* label, unsigned char *ciphertxt, int len);
        int SM9MsgSend(SM9RegisterMsg *SM9Msg);
        void forwardMessage(SM9RegisterMsg *SM9Msg);
        virtual ~A() override;

    protected:
        virtual void initialize() override;
        virtual void handleMessage(cMessage *sm9signMsg) override ;
        virtual void finish() override;

    public:
        struct SM9_REG_PARAM_T PubParams;
        struct SM9_VRC_REG_T RegStruct;
        struct SM9_RSU_REG_T RSUStruct;
        BIGNUM *ks;
        BIGNUM *krj;
        const char *id = "R-U100-LN2313";
        const char *idA;
        double pos[2] = {23.45, 56.93};
        unsigned char *Prj;
        unsigned char *Kra;
        double threshold = 5.0;

};

class B: public cSimpleModule
{
    private:
        int SM9MsgSend(SM9RegisterMsg *SM9Msg);
        SM9RegisterMsg* VRCRegSetup();
        int SendResponse(int flag);
        void forwardMessage(SM9RegisterMsg *SM9Msg);
        int Key_write(const char* id, char *memberKey, char *regionKey, unsigned char *point_rj, unsigned char *point_pubs);
        int isAuthenticatedRSU(struct SM9_RSU_REG_T t);
        virtual ~B() override;

    protected:
        virtual void initialize(void) override;
        virtual void handleMessage(cMessage *msg) override ;

    public:
        struct SM9_REG_PARAM_T PubParams;
        struct SM9_RSU_REG_T RSUStruct;
        const char *id = "X-Alice-CL8038-13123459876";
        BIGNUM *TA;
        unsigned char *RLP;
        unsigned char *Kra;
        unsigned char *Prj;
        char *dsa;
        char *dsra;


};




#endif /* SM9REGISTER_H_ */
