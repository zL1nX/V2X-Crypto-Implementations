//
// Generated file, do not edit! Created by nedtool 5.3 from sm2Sign.msg.
//

// Disable warnings about unused variables, empty switch stmts, etc:
#ifdef _MSC_VER
#  pragma warning(disable:4101)
#  pragma warning(disable:4065)
#endif

#if defined(__clang__)
#  pragma clang diagnostic ignored "-Wshadow"
#  pragma clang diagnostic ignored "-Wconversion"
#  pragma clang diagnostic ignored "-Wunused-parameter"
#  pragma clang diagnostic ignored "-Wc++98-compat"
#  pragma clang diagnostic ignored "-Wunreachable-code-break"
#  pragma clang diagnostic ignored "-Wold-style-cast"
#elif defined(__GNUC__)
#  pragma GCC diagnostic ignored "-Wshadow"
#  pragma GCC diagnostic ignored "-Wconversion"
#  pragma GCC diagnostic ignored "-Wunused-parameter"
#  pragma GCC diagnostic ignored "-Wold-style-cast"
#  pragma GCC diagnostic ignored "-Wsuggest-attribute=noreturn"
#  pragma GCC diagnostic ignored "-Wfloat-conversion"
#endif

#include <iostream>
#include <sstream>
#include "sm2Sign_m.h"

namespace omnetpp {

// Template pack/unpack rules. They are declared *after* a1l type-specific pack functions for multiple reasons.
// They are in the omnetpp namespace, to allow them to be found by argument-dependent lookup via the cCommBuffer argument

// Packing/unpacking an std::vector
template<typename T, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::vector<T,A>& v)
{
    int n = v.size();
    doParsimPacking(buffer, n);
    for (int i = 0; i < n; i++)
        doParsimPacking(buffer, v[i]);
}

template<typename T, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::vector<T,A>& v)
{
    int n;
    doParsimUnpacking(buffer, n);
    v.resize(n);
    for (int i = 0; i < n; i++)
        doParsimUnpacking(buffer, v[i]);
}

// Packing/unpacking an std::list
template<typename T, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::list<T,A>& l)
{
    doParsimPacking(buffer, (int)l.size());
    for (typename std::list<T,A>::const_iterator it = l.begin(); it != l.end(); ++it)
        doParsimPacking(buffer, (T&)*it);
}

template<typename T, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::list<T,A>& l)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i=0; i<n; i++) {
        l.push_back(T());
        doParsimUnpacking(buffer, l.back());
    }
}

// Packing/unpacking an std::set
template<typename T, typename Tr, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::set<T,Tr,A>& s)
{
    doParsimPacking(buffer, (int)s.size());
    for (typename std::set<T,Tr,A>::const_iterator it = s.begin(); it != s.end(); ++it)
        doParsimPacking(buffer, *it);
}

template<typename T, typename Tr, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::set<T,Tr,A>& s)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i=0; i<n; i++) {
        T x;
        doParsimUnpacking(buffer, x);
        s.insert(x);
    }
}

// Packing/unpacking an std::map
template<typename K, typename V, typename Tr, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::map<K,V,Tr,A>& m)
{
    doParsimPacking(buffer, (int)m.size());
    for (typename std::map<K,V,Tr,A>::const_iterator it = m.begin(); it != m.end(); ++it) {
        doParsimPacking(buffer, it->first);
        doParsimPacking(buffer, it->second);
    }
}

template<typename K, typename V, typename Tr, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::map<K,V,Tr,A>& m)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i=0; i<n; i++) {
        K k; V v;
        doParsimUnpacking(buffer, k);
        doParsimUnpacking(buffer, v);
        m[k] = v;
    }
}

// Default pack/unpack function for arrays
template<typename T>
void doParsimArrayPacking(omnetpp::cCommBuffer *b, const T *t, int n)
{
    for (int i = 0; i < n; i++)
        doParsimPacking(b, t[i]);
}

template<typename T>
void doParsimArrayUnpacking(omnetpp::cCommBuffer *b, T *t, int n)
{
    for (int i = 0; i < n; i++)
        doParsimUnpacking(b, t[i]);
}

// Default rule to prevent compiler from choosing base class' doParsimPacking() function
template<typename T>
void doParsimPacking(omnetpp::cCommBuffer *, const T& t)
{
    throw omnetpp::cRuntimeError("Parsim error: No doParsimPacking() function for type %s", omnetpp::opp_typename(typeid(t)));
}

template<typename T>
void doParsimUnpacking(omnetpp::cCommBuffer *, T& t)
{
    throw omnetpp::cRuntimeError("Parsim error: No doParsimUnpacking() function for type %s", omnetpp::opp_typename(typeid(t)));
}

}  // namespace omnetpp


// forward
template<typename T, typename A>
std::ostream& operator<<(std::ostream& out, const std::vector<T,A>& vec);

// Template rule which fires if a struct or class doesn't have operator<<
template<typename T>
inline std::ostream& operator<<(std::ostream& out,const T&) {return out;}

// operator<< for std::vector<T>
template<typename T, typename A>
inline std::ostream& operator<<(std::ostream& out, const std::vector<T,A>& vec)
{
    out.put('{');
    for(typename std::vector<T,A>::const_iterator it = vec.begin(); it != vec.end(); ++it)
    {
        if (it != vec.begin()) {
            out.put(','); out.put(' ');
        }
        out << *it;
    }
    out.put('}');
    
    char buf[32];
    sprintf(buf, " (size=%u)", (unsigned int)vec.size());
    out.write(buf, strlen(buf));
    return out;
}

Register_Class(sm2signMsg_t)

sm2signMsg_t::sm2signMsg_t(const char *name, short kind) : ::omnetpp::cMessage(name,kind)
{
    this->siglen = 0;
    this->flag = 0;
    this->received = 0;
}

sm2signMsg_t::sm2signMsg_t(const sm2signMsg_t& other) : ::omnetpp::cMessage(other)
{
    copy(other);
}

sm2signMsg_t::~sm2signMsg_t()
{
}

sm2signMsg_t& sm2signMsg_t::operator=(const sm2signMsg_t& other)
{
    if (this==&other) return *this;
    ::omnetpp::cMessage::operator=(other);
    copy(other);
    return *this;
}

void sm2signMsg_t::copy(const sm2signMsg_t& other)
{
    this->sigR = other.sigR;
    this->sigS = other.sigS;
    this->dgst = other.dgst;
    this->hashmsg = other.hashmsg;
    this->siglen = other.siglen;
    this->flag = other.flag;
    this->received = other.received;
}

void sm2signMsg_t::parsimPack(omnetpp::cCommBuffer *b) const
{
    ::omnetpp::cMessage::parsimPack(b);
    doParsimPacking(b,this->sigR);
    doParsimPacking(b,this->sigS);
    doParsimPacking(b,this->dgst);
    doParsimPacking(b,this->hashmsg);
    doParsimPacking(b,this->siglen);
    doParsimPacking(b,this->flag);
    doParsimPacking(b,this->received);
}

void sm2signMsg_t::parsimUnpack(omnetpp::cCommBuffer *b)
{
    ::omnetpp::cMessage::parsimUnpack(b);
    doParsimUnpacking(b,this->sigR);
    doParsimUnpacking(b,this->sigS);
    doParsimUnpacking(b,this->dgst);
    doParsimUnpacking(b,this->hashmsg);
    doParsimUnpacking(b,this->siglen);
    doParsimUnpacking(b,this->flag);
    doParsimUnpacking(b,this->received);
}

cBIGNUM& sm2signMsg_t::getSigR()
{
    return this->sigR;
}

void sm2signMsg_t::setSigR(const cBIGNUM& sigR)
{
    this->sigR = sigR;
}

cBIGNUM& sm2signMsg_t::getSigS()
{
    return this->sigS;
}

void sm2signMsg_t::setSigS(const cBIGNUM& sigS)
{
    this->sigS = sigS;
}

pchar& sm2signMsg_t::getDgst()
{
    return this->dgst;
}

void sm2signMsg_t::setDgst(const pchar& dgst)
{
    this->dgst = dgst;
}

const char * sm2signMsg_t::getHashmsg() const
{
    return this->hashmsg.c_str();
}

void sm2signMsg_t::setHashmsg(const char * hashmsg)
{
    this->hashmsg = hashmsg;
}

int sm2signMsg_t::getSiglen() const
{
    return this->siglen;
}

void sm2signMsg_t::setSiglen(int siglen)
{
    this->siglen = siglen;
}

int sm2signMsg_t::getFlag() const
{
    return this->flag;
}

void sm2signMsg_t::setFlag(int flag)
{
    this->flag = flag;
}

int sm2signMsg_t::getReceived() const
{
    return this->received;
}

void sm2signMsg_t::setReceived(int received)
{
    this->received = received;
}

class sm2signMsg_tDescriptor : public omnetpp::cClassDescriptor
{
  private:
    mutable const char **propertynames;
  public:
    sm2signMsg_tDescriptor();
    virtual ~sm2signMsg_tDescriptor();

    virtual bool doesSupport(omnetpp::cObject *obj) const override;
    virtual const char **getPropertyNames() const override;
    virtual const char *getProperty(const char *propertyname) const override;
    virtual int getFieldCount() const override;
    virtual const char *getFieldName(int field) const override;
    virtual int findField(const char *fieldName) const override;
    virtual unsigned int getFieldTypeFlags(int field) const override;
    virtual const char *getFieldTypeString(int field) const override;
    virtual const char **getFieldPropertyNames(int field) const override;
    virtual const char *getFieldProperty(int field, const char *propertyname) const override;
    virtual int getFieldArraySize(void *object, int field) const override;

    virtual const char *getFieldDynamicTypeString(void *object, int field, int i) const override;
    virtual std::string getFieldValueAsString(void *object, int field, int i) const override;
    virtual bool setFieldValueAsString(void *object, int field, int i, const char *value) const override;

    virtual const char *getFieldStructName(int field) const override;
    virtual void *getFieldStructValuePointer(void *object, int field, int i) const override;
};

Register_ClassDescriptor(sm2signMsg_tDescriptor)

sm2signMsg_tDescriptor::sm2signMsg_tDescriptor() : omnetpp::cClassDescriptor("sm2signMsg_t", "omnetpp::cMessage")
{
    propertynames = nullptr;
}

sm2signMsg_tDescriptor::~sm2signMsg_tDescriptor()
{
    delete[] propertynames;
}

bool sm2signMsg_tDescriptor::doesSupport(omnetpp::cObject *obj) const
{
    return dynamic_cast<sm2signMsg_t *>(obj)!=nullptr;
}

const char **sm2signMsg_tDescriptor::getPropertyNames() const
{
    if (!propertynames) {
        static const char *names[] = {  nullptr };
        omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
        const char **basenames = basedesc ? basedesc->getPropertyNames() : nullptr;
        propertynames = mergeLists(basenames, names);
    }
    return propertynames;
}

const char *sm2signMsg_tDescriptor::getProperty(const char *propertyname) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    return basedesc ? basedesc->getProperty(propertyname) : nullptr;
}

int sm2signMsg_tDescriptor::getFieldCount() const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    return basedesc ? 7+basedesc->getFieldCount() : 7;
}

unsigned int sm2signMsg_tDescriptor::getFieldTypeFlags(int field) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldTypeFlags(field);
        field -= basedesc->getFieldCount();
    }
    static unsigned int fieldTypeFlags[] = {
        FD_ISCOMPOUND,
        FD_ISCOMPOUND,
        FD_ISCOMPOUND,
        FD_ISEDITABLE,
        FD_ISEDITABLE,
        FD_ISEDITABLE,
        FD_ISEDITABLE,
    };
    return (field>=0 && field<7) ? fieldTypeFlags[field] : 0;
}

const char *sm2signMsg_tDescriptor::getFieldName(int field) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldName(field);
        field -= basedesc->getFieldCount();
    }
    static const char *fieldNames[] = {
        "sigR",
        "sigS",
        "dgst",
        "hashmsg",
        "siglen",
        "flag",
        "received",
    };
    return (field>=0 && field<7) ? fieldNames[field] : nullptr;
}

int sm2signMsg_tDescriptor::findField(const char *fieldName) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    int base = basedesc ? basedesc->getFieldCount() : 0;
    if (fieldName[0]=='s' && strcmp(fieldName, "sigR")==0) return base+0;
    if (fieldName[0]=='s' && strcmp(fieldName, "sigS")==0) return base+1;
    if (fieldName[0]=='d' && strcmp(fieldName, "dgst")==0) return base+2;
    if (fieldName[0]=='h' && strcmp(fieldName, "hashmsg")==0) return base+3;
    if (fieldName[0]=='s' && strcmp(fieldName, "siglen")==0) return base+4;
    if (fieldName[0]=='f' && strcmp(fieldName, "flag")==0) return base+5;
    if (fieldName[0]=='r' && strcmp(fieldName, "received")==0) return base+6;
    return basedesc ? basedesc->findField(fieldName) : -1;
}

const char *sm2signMsg_tDescriptor::getFieldTypeString(int field) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldTypeString(field);
        field -= basedesc->getFieldCount();
    }
    static const char *fieldTypeStrings[] = {
        "cBIGNUM",
        "cBIGNUM",
        "pchar",
        "string",
        "int",
        "int",
        "int",
    };
    return (field>=0 && field<7) ? fieldTypeStrings[field] : nullptr;
}

const char **sm2signMsg_tDescriptor::getFieldPropertyNames(int field) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldPropertyNames(field);
        field -= basedesc->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    }
}

const char *sm2signMsg_tDescriptor::getFieldProperty(int field, const char *propertyname) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldProperty(field, propertyname);
        field -= basedesc->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    }
}

int sm2signMsg_tDescriptor::getFieldArraySize(void *object, int field) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldArraySize(object, field);
        field -= basedesc->getFieldCount();
    }
    sm2signMsg_t *pp = (sm2signMsg_t *)object; (void)pp;
    switch (field) {
        default: return 0;
    }
}

const char *sm2signMsg_tDescriptor::getFieldDynamicTypeString(void *object, int field, int i) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldDynamicTypeString(object,field,i);
        field -= basedesc->getFieldCount();
    }
    sm2signMsg_t *pp = (sm2signMsg_t *)object; (void)pp;
    switch (field) {
        default: return nullptr;
    }
}

std::string sm2signMsg_tDescriptor::getFieldValueAsString(void *object, int field, int i) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldValueAsString(object,field,i);
        field -= basedesc->getFieldCount();
    }
    sm2signMsg_t *pp = (sm2signMsg_t *)object; (void)pp;
    switch (field) {
        case 0: {std::stringstream out; out << pp->getSigR(); return out.str();}
        case 1: {std::stringstream out; out << pp->getSigS(); return out.str();}
        case 2: {std::stringstream out; out << pp->getDgst(); return out.str();}
        case 3: return oppstring2string(pp->getHashmsg());
        case 4: return long2string(pp->getSiglen());
        case 5: return long2string(pp->getFlag());
        case 6: return long2string(pp->getReceived());
        default: return "";
    }
}

bool sm2signMsg_tDescriptor::setFieldValueAsString(void *object, int field, int i, const char *value) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->setFieldValueAsString(object,field,i,value);
        field -= basedesc->getFieldCount();
    }
    sm2signMsg_t *pp = (sm2signMsg_t *)object; (void)pp;
    switch (field) {
        case 3: pp->setHashmsg((value)); return true;
        case 4: pp->setSiglen(string2long(value)); return true;
        case 5: pp->setFlag(string2long(value)); return true;
        case 6: pp->setReceived(string2long(value)); return true;
        default: return false;
    }
}

const char *sm2signMsg_tDescriptor::getFieldStructName(int field) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldStructName(field);
        field -= basedesc->getFieldCount();
    }
    switch (field) {
        case 0: return omnetpp::opp_typename(typeid(cBIGNUM));
        case 1: return omnetpp::opp_typename(typeid(cBIGNUM));
        case 2: return omnetpp::opp_typename(typeid(pchar));
        default: return nullptr;
    };
}

void *sm2signMsg_tDescriptor::getFieldStructValuePointer(void *object, int field, int i) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldStructValuePointer(object, field, i);
        field -= basedesc->getFieldCount();
    }
    sm2signMsg_t *pp = (sm2signMsg_t *)object; (void)pp;
    switch (field) {
        case 0: return (void *)(&pp->getSigR()); break;
        case 1: return (void *)(&pp->getSigS()); break;
        case 2: return (void *)(&pp->getDgst()); break;
        default: return nullptr;
    }
}


