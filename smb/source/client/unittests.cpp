//
// unittests.cpp -
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
#include "smb2utils.hpp"

#include "smbdefs.h"

#include "client.h"
#include <wireobjects.hpp>
#include <netstreambuffer.hpp>
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

static void TestBuffering();

class TestWireObjects {
    public:
     TestWireObjects()
     {
      TestBuffering();
      unsigned char test_storage[512];
      cout_log(LL_TESTS)  << "*** Testing wire objects *** " << endl;

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
    cout_log(LL_TESTS)  << endl << "Testing blob field types" << endl;
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
    if (test_value <= 0xff)       cout_log(LL_TESTS)  << "(byte)" << (int)(byte)TestObject.test_byte() << endr;
    if (test_value <= 0xffff)     cout_log(LL_TESTS)  << "(word)" << (word)TestObject.test_word() << endr;
    if (test_value <= 0xffffffff) cout_log(LL_TESTS)  << "(dword)" << (dword)TestObject.test_dword() << endr;
    if (test_value <= 0xffffff)   cout_log(LL_TESTS)  << "(24bitword)" << (dword)TestObject.test_24bitword() << endr;
                                  cout_log(LL_TESTS)  << "(ddword)" << (ddword)TestObject.test_ddword() << endr;
    if (test_value >= (int) 'A' && test_value <= (int) 'Z')
    {
       std::string result_string = std::string ((const char *)TestObject.test_blob4());
       cout_log(LL_TESTS)  << "(blob4)" << result_string << endl;
       std::string result_string1 = std::string ((const char *)TestObject.test_FileId());
       cout_log(LL_TESTS)  << "(FileId)" << result_string1 << endl;
       std::string result_string2 = std::string ((const char *)TestObject.test_blob16());
       cout_log(LL_TESTS)  << "(blob16)" << result_string2 << endl;
//     cout_log(LL_TESTS)  << "(blob)" << (blob)TestObject.test_blob() << endl;
    }
    if (test_value == (int) 'Z')
     cout_log(LL_TESTS)  << endl << "Finished testing blob field types" << endl;
   }
   cout_log(LL_TESTS)  << endl << "Finished !!!!" << endl;
//   while (1)
//    cout_log(LL_TESTS)  << "Finished !!!!" << endr;
   }
};

TestWireObjects PerformTestWireObjects;
void include_wiretests()
{
//cout_log(LL_TESTS)  << "=== callme === # " << endl;
// TestWireObjects PerformTestWireObjects;
//cout_log(LL_TESTS)  << "=== callme 2 === # " << endl;
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

#define TESTBUFFER_SIZE_D (32768+129)
#define TESTBUFFER_SIZE (dword)(TESTBUFFER_SIZE_D*4)
static void _TestBufferingType(int test_buffertype);
static void TestBuffering()
{
   _TestBufferingType(0);
   _TestBufferingType(1);
  _TestBufferingType(2);

}
static void _TestBufferingType(int test_buffertype)
{
    dword source_pattern[TESTBUFFER_SIZE_D];
    byte  test_buffer_storage[TESTBUFFER_SIZE];
    byte  pull_buffer[TESTBUFFER_SIZE];
    dword index = 0;

//    std::for_each(nums.begin(), nums.end(), [](int &n, &index){ n = index++; });
    for(dword i=0;i<TESTBUFFER_SIZE_D;i++) source_pattern[i]=i;

    cout_log(LL_TESTS)  << "*** Testing NetStreamBuffer object *** type: " << test_buffertype << endl;
    NetStreamBuffer  TestBuffer;
    cout_log(LL_TESTS)  << "*** Filling NetStreamBuffer object *** " << endl;
    StreamBufferDataSource TestDataSource;

    memcpydevContext cpydevContext = {(byte *) source_pattern,TESTBUFFER_SIZE };
    TestDataSource.SourceFromDevice (memcpy_source_function, (void *)&cpydevContext);

//    TestDataSource.SourceFromMemory((byte *) source_pattern, TESTBUFFER_SIZE);

    TestBuffer.attach_buffer(test_buffer_storage, sizeof(test_buffer_storage));
    TestBuffer.attach_source(TestDataSource);
    dword  buffered_byte_count;
    dword bytes_pulled = 0;
    byte  *s = (byte *) source_pattern;
    do
    {
      cout_log(LL_TESTS)  << "*** Pulling *** " << endl;
      byte   *read_buffer_pointer;
      read_buffer_pointer = TestBuffer.peek_input(buffered_byte_count);
      cout_log(LL_TESTS)  << "*** Peeked nbytes: " << buffered_byte_count << " bytes" << endl;

      if (test_buffertype==0)
      {
      struct memcpydevContext myContext = {pull_buffer, 1024};
      DataSinkDevtype TestDeviceSink(memcpy_sink_function, (void *)&myContext);
//   NetStatus pull_input(MemoryDataSink &_data_sink, dword byte_count, dword &bytes_pulled, dword min_byte_count=1)
      TestBuffer.attach_sink(&TestDeviceSink);
//      if (TestBuffer.pull_input(&TestDeviceSink, (dword)1024, bytes_pulled) != NetStatusOk)
      if (TestBuffer.pull_input((dword)1024, bytes_pulled) != NetStatusOk)
      {
        cout_log(LL_TESTS)  << "*** DataSinkDevtype Pull failed *** " << endl;
        break;
      }
      }
      if (test_buffertype==1)
      {
      MemoryDataSink TestMemoryDataSink;     // works okay
      TestMemoryDataSink.SinkToMemory(pull_buffer, 1024);
      TestBuffer.attach_sink(&TestMemoryDataSink);
      if (TestBuffer.pull_input(1024, bytes_pulled) != NetStatusOk)
//      if (TestBuffer.pull_input(TestMemoryDataSink, 1024, bytes_pulled) != NetStatusOk)
      {
        cout_log(LL_TESTS)  << "*** MemoryDataSink Pull failed *** " << endl;
        break;
      }
      }
      if (test_buffertype==2)
      {
      if (TestBuffer.pull_input(pull_buffer, 1024, bytes_pulled) != NetStatusOk)
      {
        cout_log(LL_TESTS)  << "*** pull_buffer Pull failed *** " << endl;
        break;
      }
}
      if (tc_memcmp(pull_buffer, s, bytes_pulled) != 0)
      {
        cout_log(LL_TESTS)  << "*** pullr compare failed *** " << endl;
        break;
      }
      s += bytes_pulled;
    } while (bytes_pulled!=0);
}
