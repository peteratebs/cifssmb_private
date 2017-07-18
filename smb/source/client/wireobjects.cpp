//
// smb2wireobjects.cpp -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2018
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//  SMB2 client session level interface
//
#include <map>
#include <algorithm>
#include <iostream>
#include <string>
using std::cout;
using std::endl;

#include "smbdefs.h"

#ifdef SUPPORT_SMB2   /* exclude rest of file */

#if (INCLUDE_RTSMB_CLIENT)
#include "client.h"
#include <wireobjects.hpp>
#include <smb2wireobjects.hpp>



// Use static initializer constructor to intitialize run time table
static std::string endr = std::string (15, (char) ' ') + "\r";
class NetTestObject  : public NetWireStruct   {
  public:
   NetTestObject() {}
   NetWirebyte       test_byte;
   NetWireword       test_word;
   NetWiredword      test_dword;
   NetWireddword     test_ddword;
   NetWireblob4      test_blob4;
   NetWireFileId     test_FileId;
   NetWire24bitword  test_24bitword;
   NetWireblob16     test_blob16;
   NetWireblob       test_blob;
   int  FixedStructureSize()  { return 4; };
   byte *FixedStructureAddress()                  { return 0; };
   void SetDefaults()  { };
   unsigned char *bindpointers(byte *_raw_address) {
        BindAddressesToBuffer( _raw_address);
        return _raw_address+4;}
private:
  void BindAddressOpen(BindNetWireArgs & args)  {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};


class TestWireObjects {
    public:
     TestWireObjects()
     {
      unsigned char test_storage[512];
      cout << "*** Testing wire objects *** " << endl;
      NetTestObject TestObject;

    TestObject.bindpointers(test_storage);
//    for (ddword test_value = (ddword) 0;  test_value < (ddword) 0xffffff; test_value++) {
    for (ddword test_value = (ddword) 0;  test_value < (ddword) 0xfff; test_value++) {

    if (test_value <= 0xff)      TestObject.test_byte =  (byte  ) test_value;
    if (test_value <= 0xffff)    TestObject.test_word =  (word  ) test_value;
    if (test_value <= 0xffffffff)TestObject.test_dword = (dword ) test_value;
    if (test_value <= 0xffffff)  TestObject.test_24bitword =(dword) test_value;
                                 TestObject.test_ddword =(ddword) test_value;

//     byte   test_byte =  (byte  ) test_value;
//     word   test_word =  (word  ) test_value;
//     dword  test_dword = (dword ) test_value;
//     ddword test_ddword =(ddword) test_value;
    if (test_value == (int) 'A')
    cout << endl << "Testing blob field types" << endl;
    if (test_value >= (int) 'A' && test_value <= (int) 'Z')
    {
       std::string test_string = std::string (3, (char) test_value);
       TestObject.test_blob4 = (byte *)test_string.c_str();
       std::string test_string1 = std::string (15, (char) test_value);
       TestObject.test_FileId = (byte *)test_string1.c_str();
       std::string test_string2 = std::string (15, (char) test_value);
       TestObject.test_blob16 = (byte *)test_string2.c_str();
//     test_blob = (blob) test_value;
    }
    if (test_value <= 0xff)       cout << "(byte)" << (int)(byte)TestObject.test_byte.get() << endr;
    if (test_value <= 0xffff)     cout << "(word)" << (word)TestObject.test_word.get() << endr;
    if (test_value <= 0xffffffff) cout << "(dword)" << (dword)TestObject.test_dword.get() << endr;
    if (test_value <= 0xffffff)   cout << "(24bitword)" << (dword)TestObject.test_24bitword.get() << endr;
                                  cout << "(ddword)" << (ddword)TestObject.test_ddword.get() << endr;
    if (test_value >= (int) 'A' && test_value <= (int) 'Z')
    {
       std::string result_string = std::string ((const char *)TestObject.test_blob4.get());
       cout << "(blob4)" << result_string << endl;
       std::string result_string1 = std::string ((const char *)TestObject.test_FileId.get());
       cout << "(FileId)" << result_string1 << endl;
       std::string result_string2 = std::string ((const char *)TestObject.test_blob16.get());
       cout << "(blob16)" << result_string2 << endl;
//     cout << "(blob)" << (blob)TestObject.test_blob.get() << endl;
    }
    if (test_value == (int) 'Z')
     cout << endl << "Finished testing blob field types" << endl;
   }
   cout << endl << "Finished !!!!" << endl;
    }
};

TestWireObjects PerformTestWireObjects;
void include_wiretests()
{
//cout << "=== callme === # " << endl;
// TestWireObjects PerformTestWireObjects;
//cout << "=== callme 2 === # " << endl;
}

/// ===============================

void NetTestObject::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(test_byte);
  BINDPOINTERS(test_word);
  BINDPOINTERS(test_dword);
  BINDPOINTERS(test_ddword);
  BINDPOINTERS(test_blob4);
  BINDPOINTERS(test_FileId);
  BINDPOINTERS(test_24bitword);
  BINDPOINTERS(test_blob16);
  BINDPOINTERS(test_blob);
}

#endif /* INCLUDE_RTSMB_CLIENT */
#endif

