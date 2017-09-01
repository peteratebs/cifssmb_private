
//
// smb2wireobjects.hpp -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2017
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//
//
#ifndef include_wireobjects
#define include_wireobjects


#define HTONETWORD(D)   tc_memcpy(raw_address, &D, sizeof(word))
#define NETTOHWORD(D)   tc_memcpy(&D, raw_address, sizeof(word))
#define HTONETDWORD(D)  tc_memcpy(raw_address, &D, sizeof(dword))
#define NETTOHDWORD(D)  tc_memcpy(&D, raw_address, sizeof(dword))
#define HTONETDDWORD(D) tc_memcpy(raw_address, &D, sizeof(ddword))
#define NETTOHDDWORD(D) tc_memcpy(&D, raw_address, sizeof(ddword))

// Type passed when we enumerate fields to bind network data in a buffer to smart pointers
class BindNetWireArgs {
public:
  BindNetWireArgs();
  BindNetWireArgs(byte * _raw_address) { raw_address=_raw_address;}
  void operator =(byte *d)  { raw_address = d;};
  byte * raw_address;
};

// base class for all network primitives
class NetWire {
  public:
    NetWire() {}
    virtual void bindpointers(BindNetWireArgs &args)
    {
        raw_address = args.raw_address;
        args.raw_address+=blob_size;
    }
    // used internally by blob types but can be used to get a pointer view of  numeric data too
    virtual const byte *get_raw_address()  { return raw_address; };
private:
protected:
   int blob_size;
   byte * raw_address;
    virtual void set(void *p)  { tc_memcpy(raw_address, p, blob_size);}
    // base class method for when we enumerate fields to bind network data in a buffer to smart pointers
    virtual void bindpointers(BindNetWireArgs &args, int size) {
        raw_address = args.raw_address;
        blob_size = size;
        args.raw_address+=blob_size;
    }

};

//  Smart classes that inheret from NetWire
//   get(&X) memcopies blobs or copies the primitive to X
//   get() for blobs or get_raw_address() for primitive returns a pointer to the raw buffer.
//   = is overloaded for assignment to  NetWirebyte MyVar = 1;
//  class NetWirebyte
//  class NetWireword
//  class NetWiredword
//  class NetWireddword
//  class NetWireblob
//  class NetWireblob16
//  class NetWireblob4
//  class NetWireFileId
//  class NetWire24bitword



class NetWirebyte  : public NetWire {
  public:
    NetWirebyte() {blob_size=1;}
    void operator =(byte d)  { *((byte *)raw_address) = d;rv=d;}; // override equal operator

    byte operator()() {
        return get();
    }
   private:
    byte rv;
    byte get()  { return (byte)*raw_address;}
};

class NetWireword  : public NetWire {
  public:
    NetWireword() {blob_size=2;};
    void operator =(word d)  { HTONETWORD(d);rv=d; }; // memcpy(raw_address, &d, sizeof(word));}
    word operator()() { return get(); }
   private:
    word rv;
    word get()  { word v; NETTOHWORD(v);return v;}
};

class NetWiredword  : public NetWire {
  public:
    NetWiredword() {blob_size=4;}
    void operator =(dword d)  { HTONETDWORD(d);rv=d;}; // memcpy(raw_address, &d, sizeof(dword));}
    dword operator()() { return get(); }
   private:
    dword rv;
    dword get()  { dword v; NETTOHDWORD(v);return v;}
};

class NetWireddword  : public NetWire {
  public:
    NetWireddword() {blob_size=8;}
    ddword operator()() { return get(); }
    void operator =(ddword d)  { HTONETDDWORD(d); rv=d;}; // memcpy(raw_address, &d, sizeof(ddword));}
   private:
    ddword rv;
    ddword get()  { ddword v; NETTOHDDWORD(v);return v;}
};

class NetWireFileTime  : public NetWire {
  public:
    NetWireFileTime() {blob_size=8;};
    ddword operator()() { return get(); }
    void operator =(ddword d)  { HTONETDDWORD(d); rv=d;} // memcpy(raw_address, &d, sizeof(ddword));}
   private:
    ddword rv;
    ddword get()   { ddword v; NETTOHDDWORD(v);return v;}
};


class NetWireblob  : public NetWire {
  public:
    NetWireblob() {blob_size=0;}
    NetWireblob(int size) {blob_size=size;}
protected:
    void get(void *p)
    {
         tc_memcpy(p, raw_address, blob_size);
    }
private:
};


class NetWireblob24  : public NetWireblob {
  public:
    void operator =(byte *s)  { tc_memcpy(raw_address, s, blob_size);};
    NetWireblob24() {blob_size=24;};
    void get(void *p)  { NetWireblob::get(p); };
    const byte *operator()() { return get(); }
   private:
    const byte *get()  { return get_raw_address(); };
};

class NetWireblob16  : public NetWireblob {
  public:
    void operator =(byte *s)  { tc_memcpy(raw_address, s, blob_size);};
    NetWireblob16() {blob_size=16;};
    void get(void *p)  { NetWireblob::get(p); };
    const byte *operator()() { return get(); }
   private:
    const byte *get()  { return get_raw_address(); };
};
class NetWireblob8  : public NetWireblob {
  public:
    void operator =(byte *s)  { tc_memcpy(raw_address, s, blob_size);};
    NetWireblob8() { blob_size=8;};
    void get(void *p)  { NetWireblob::get(p); };
    const byte *operator()() { return get(); }
   private:
    const byte *get()  { return get_raw_address(); };
};

class NetWireblob7  : public NetWireblob {
  public:
    void operator =(byte *s)  { tc_memcpy(raw_address, s, blob_size);};
    NetWireblob7() { blob_size=7;};
    void get(void *p)  { NetWireblob::get(p); };
    const byte *operator()() { return get(); }
   private:
    const byte *get()  { return get_raw_address(); };
};

class NetWireblob4  : public NetWireblob {
  public:
    void operator =(byte *s)  { tc_memcpy(raw_address, s, blob_size);};
    NetWireblob4() { blob_size=4;};
    void get(void *p)  { NetWireblob::get(p); };
    const byte *operator()() { return get(); }
   private:
    const byte *get()  { return get_raw_address(); };
};

class NetWireFileId  : public NetWireblob {
  public:
    NetWireFileId() {blob_size=16;};
    void operator =(byte *s)  { tc_memcpy(raw_address, s, blob_size);};
    void get(void *p)  { NetWireblob::get(p); };
    const byte *operator()() { return get(); }
   private:
    const byte *get()  { return get_raw_address(); };
};



// Should be byte order independent
class NetWire24bitword  : public NetWireblob {
public:
    NetWire24bitword() {blob_size=3;};
    void operator =(dword d)  { set(d); }; // memcpy(raw_address, &d, sizeof(ddword));}
    dword operator()() { return get(); }
private:
    dword get()  {
         byte buf[3];
         NetWireblob::get(buf);
         dword v = 0;v |= buf[0]; v<<=8; v |= buf[1]; v<<=8; v |= buf[2];
         return v;
    }
private:
    void set(dword v)  {
        byte buf[3]; buf[0] = (v>>16)&0xff;  buf[1] = (v>>8)&0xff; buf[2] = v&0xff;
        NetWire::set(buf);
    }
};


#define BINDPOINTERS(O) (void) O.bindpointers(A)

// base class for all network structures build from primitives
// pure virtual class forces implementations to not compile without required methods.
class NetWireStruct   {
public:
  NetWireStruct() { isvariable = false; base_address=0; variablesize=0;};
  virtual const char *command_name() = 0;
  virtual const int  command_id() = 0;
  virtual int  PackedStructureSize() = 0;   // must be overridden FixedStructureSize() or FixedStructureSize()-1 if the one byte buffer size if it is a variable length message.
  virtual int  FixedStructureSize()  { return (int)objectsize; };
  virtual void addto_variable_content(dword delta_variablesize) {variablesize += delta_variablesize;};
  virtual void push_output(NetStreamOutputBuffer  &StreamBuffer) {    StreamBuffer.add_to_buffer_count(objectsize+variablesize); }

protected:
  byte *base_address;
  virtual void BindAddressOpen(BindNetWireArgs & args) = 0;
  virtual void BindAddressClose(BindNetWireArgs & args) = 0;
  virtual void BindAddressesToBuffer(byte *base) = 0;
//  virtual int  FixedStructureSize() = 0;
  virtual byte *FixedStructureAddress() = 0;
  virtual void SetDefaults() = 0;

  bool isvariable;
  dword objectsize;
  dword variablesize;
};
#endif // include_wireobjects
