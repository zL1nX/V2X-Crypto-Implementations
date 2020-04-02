//
// Generated file, do not edit! Created by nedtool 5.3 from SM9Register.msg.
//

#if defined(__clang__)
#  pragma clang diagnostic ignored "-Wreserved-id-macro"
#endif
#ifndef __SM9REGISTER_M_H
#define __SM9REGISTER_M_H

#include <omnetpp.h>

// nedtool version check
#define MSGC_VERSION 0x0503
#if (MSGC_VERSION!=OMNETPP_VERSION)
#    error Version mismatch! Probably this file was generated by an earlier version of nedtool: 'make clean' should help.
#endif



// cplusplus {{
    #include "SM9Reg_util.h"
// }}

/**
 * Class generated from <tt>SM9Register.msg:25</tt> by nedtool.
 * <pre>
 * message SM9RegisterMsg
 * {
 *     SM9_VRC_REG_T PreRegister;
 *     SM9_RSU_REG_T RegionRegister;
 *     int flag;
 * }
 * </pre>
 */
class SM9RegisterMsg : public ::omnetpp::cMessage
{
  protected:
    SM9_VRC_REG_T PreRegister;
    SM9_RSU_REG_T RegionRegister;
    int flag;

  private:
    void copy(const SM9RegisterMsg& other);

  protected:
    // protected and unimplemented operator==(), to prevent accidental usage
    bool operator==(const SM9RegisterMsg&);

  public:
    SM9RegisterMsg(const char *name=nullptr, short kind=0);
    SM9RegisterMsg(const SM9RegisterMsg& other);
    virtual ~SM9RegisterMsg();
    SM9RegisterMsg& operator=(const SM9RegisterMsg& other);
    virtual SM9RegisterMsg *dup() const override {return new SM9RegisterMsg(*this);}
    virtual void parsimPack(omnetpp::cCommBuffer *b) const override;
    virtual void parsimUnpack(omnetpp::cCommBuffer *b) override;

    // field getter/setter methods
    virtual SM9_VRC_REG_T& getPreRegister();
    virtual const SM9_VRC_REG_T& getPreRegister() const {return const_cast<SM9RegisterMsg*>(this)->getPreRegister();}
    virtual void setPreRegister(const SM9_VRC_REG_T& PreRegister);
    virtual SM9_RSU_REG_T& getRegionRegister();
    virtual const SM9_RSU_REG_T& getRegionRegister() const {return const_cast<SM9RegisterMsg*>(this)->getRegionRegister();}
    virtual void setRegionRegister(const SM9_RSU_REG_T& RegionRegister);
    virtual int getFlag() const;
    virtual void setFlag(int flag);
};

inline void doParsimPacking(omnetpp::cCommBuffer *b, const SM9RegisterMsg& obj) {obj.parsimPack(b);}
inline void doParsimUnpacking(omnetpp::cCommBuffer *b, SM9RegisterMsg& obj) {obj.parsimUnpack(b);}


#endif // ifndef __SM9REGISTER_M_H
