//
// netsreambuffer.hpp -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2018
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//
//
#ifndef include_netstreambuffer
#define include_netstreambuffer

#include "smb2utils.hpp"

#include "smb2legacyheaders.hpp"
#include "smb2session.hpp"

/// Propogate status conditions up from the lowest failure level with these constants
enum NetStatus {
    NetStatusnbsseof           = 2,
    NetStatusNextsmb2Message   = 1,
    NetStatusOk                = 0,
    NetStatusFailed            = -1,
    NetStatusFull              = -2,
    NetStatusEmpty             = -3,
    NetStatusDeviceRecvFailed  = -4,
    NetStatusBadCallParms      = -5
};

struct SocketContext{
    RTP_SOCKET socket;
};

struct memcpydevContext{
    byte *pData;
    dword bytes_left;
};
/// "device for sinking bytes from a stream.
/// This memcopies to a location stored in device context.
inline int memcpy_sink_function(void *devContext, byte *pData, int size)
{
  tc_memcpy( ((struct memcpydevContext *)devContext)->pData, pData,size);
  ((struct memcpydevContext *)devContext)->pData += size;
  ((struct memcpydevContext *)devContext)->bytes_left -= size;
  return size;
}

/// device for sinking bytes to null.
inline int null_sink_function(void *devContext, byte *pData, int size)
{
  return size;
}

/// device for sinking bytes to tcp stream.
inline int socket_sink_function(void *devContext, byte *pData, int size)
{
   if (rtsmb_net_write( ((struct SocketContext *)devContext)->socket, pData,size)==0)
    return size;
   else
     return -1;
}


/// device for sourcing bytes from tcp stream.
inline int socket_source_function(void *devContext, byte *pData, int size)
{
   int r = rtsmb_net_read ( ((struct SocketContext *)devContext)->socket, pData, size, size);
   return r;
}


typedef int (* pDeviceSendFn_t) (void *devContext, byte *pData, int size);
/// Attach this to NetStreamBuffer to sink streamdata to a device
class DataSinkDevtype {
public:
  DataSinkDevtype() {}
  /// Constructor assigns a send function and a device context for the send function.
  DataSinkDevtype(pDeviceSendFn_t _DeviceSendFn,void *_DeviceContext) {DeviceSendFn=_DeviceSendFn;DeviceContext= _DeviceContext;}


  /// The sink function. Call this to send bytes to the device via the device callback
  NetStatus sink_bytes_to_device(byte *to, dword bytes_to_sink, dword &bytes_sunk)
  {
    bytes_sunk=0;
    do
    {
     int ibytes_to_sink = bytes_to_sink <= INT_MAX ? bytes_to_sink: INT_MAX;
     int ibytessent = DeviceSendFn(DeviceContext, to, ibytes_to_sink);
     if (ibytessent < 0)
       return NetStatusDeviceRecvFailed;
     bytes_to_sink -= ibytessent;
     bytes_sunk += ibytessent;
     to += ibytessent;
    } while (bytes_to_sink);
    return NetStatusOk;
  }
private:
  void *DeviceContext;
  pDeviceSendFn_t DeviceSendFn;
};


/// Attach this to NetStreamBuffer to sink streaming data to a memory device
/// Another method is also available in cases where all pull data fits in the buffer.
//  In that case you can call pull_input(byte *data, dword byte_count, dword &bytes_pulled); to recieve into the buffer
class MemoryDataSink {
public:
  MemoryDataSink() { }
  /// Call from the API to atach a buffer to the stream before calling stream.pull_input().
  void SinkToMemory (byte *data, dword _byte_count) {data_pointer=data; buffer_size=_byte_count;bytes_buffered=0;bytes_pulled=0;}

  // Called by the stream implementation to move data
  NetStatus sink_data(byte *from, dword bytes_to_sink, dword &bytes_sunk)
  {
    dword ntosink=std::min(bytes_to_sink, bytes_free());
    tc_memcpy(data_pointer+bytes_buffered,from,ntosink);
    bytes_sunk=ntosink;
    bytes_buffered += bytes_sunk;
    if (bytes_sunk==0)
      return NetStatusFull;
    else
      return NetStatusOk;
  }
private:
  dword bytes_free() { return buffer_size-bytes_buffered; }
  byte *get_sink_data_buffer(dword & bytes_available) {bytes_available=bytes_buffered-bytes_pulled; return data_pointer+bytes_pulled;}
  void  sink_data_consume(dword bytes_consumed) {bytes_pulled+=bytes_consumed;};
  byte *data_pointer;
  dword buffer_size;
  dword bytes_buffered;
  dword bytes_pulled;
};


/// Protototype device for sourcing bytes to a stream from a memory buffer.
inline int memcpy_source_function(void *devContext, byte *pData, int size)
{
  tc_memcpy(pData,((struct memcpydevContext *)devContext)->pData, size);
  ((struct memcpydevContext *)devContext)->pData += size;
  ((struct memcpydevContext *)devContext)->bytes_left -= size;
  return size;
}

typedef int (* pDeviceReceiveFn_t) (void *devContext, byte *pRecieveto, int size);

/// Attach this to NetStreamBuffer to source streamdata from a device or from memory
class StreamBufferDataSource {
public:
  StreamBufferDataSource() {devContext=0; DeviceReceiveFn=0;}
  /// Call this to provide a callback and context for sourcing data from for example, files or sockets.
  void SourceFromDevice (pDeviceReceiveFn_t _DeviceReceiveFn, void *_devContext) { DeviceReceiveFn=_DeviceReceiveFn; devContext=_devContext;}
  /// Call this to preload the stream with a buffer of data that will be pushed to the sink when the stream.pull_input is called.
  void SourceFromMemory (byte *data, dword _byte_count) { data_pointer=data; buffer_size=bytes_buffered=_byte_count; }

  // called by the stream class to source data. Copy from memory or if a function is registered call DeviceReceiveFn
  NetStatus source_data(byte *to, dword max_count, dword &bytes_sourced)
  {
    if (DeviceReceiveFn)
    {
     int n=DeviceReceiveFn(devContext,to,max_count);
     if (n < 0)
     {
       return NetStatusDeviceRecvFailed;
     }
     bytes_sourced=n;
    }
    else
    {
      dword ntosource=std::min(max_count,bytes_buffered);
      tc_memcpy(to,data_pointer,ntosource);
      bytes_sourced=ntosource;
      bytes_buffered -= bytes_sourced;
      data_pointer += bytes_sourced;
    }
    if (bytes_sourced==0)
      return NetStatusEmpty;
    else
      return NetStatusOk;
  }
private:
  void *devContext;
  pDeviceReceiveFn_t DeviceReceiveFn;
  byte *data_pointer;
  dword buffer_size;
  dword bytes_buffered;
};



/// Stream abstraction with buffering and installable data source and sinks
class NetStreamBuffer     {
public:
   NetStreamBuffer()                              {   pdevice_sink=0;pmemory_sink=0; };
   ~NetStreamBuffer()                             {};
//   smb2_iostream  *pStream;
   ///  Assign a chunk of memory to the stream for internal buffering.
   ///   should be large enough for smooth performance with sockets and files
   void attach_buffer(byte *data, dword byte_count, dword preload_count=0){ _attach_buffer(data, byte_count,preload_count); }

   ///  Tell the buffer how large the nbss frame is.
   void attach_nbss (dword nbss_size) {_attach_nbss(nbss_size);}


   /// Assign a data source for the stream, this object is configurable to source from a memory array or from a device.
   void attach_source(StreamBufferDataSource & _data_source){ data_sourcer = &_data_source; }
   /// Attach a device oriented destination to the stream.
   /// Data from the source is passed to this device object's callback routine for processing (sending, writing)
   class NetStreamBuffer *attach_sink(DataSinkDevtype *_device_sink)   { pmemory_sink=0; pdevice_sink = _device_sink; return this;}
   /// Attach a memory oriented destination to the stream.
   /// Data from the source is passed to this buffer as it is pulled from the source.
   class NetStreamBuffer *attach_sink(MemoryDataSink *_memory_sink)   { pdevice_sink=0; pmemory_sink = _memory_sink; return this;}
   NetStatus push_output(byte *output, dword byte_count)
   {
     dword bytes_free;
     byte *to= get_write_buffer_pointer(bytes_free);

     // Flush rthe output if we are full
     if (bytes_free < byte_count)
     {
       dword bytes_pulled;
       if (pdevice_sink)
          pull_input(pdevice_sink, byte_count, bytes_pulled);
       to= get_write_buffer_pointer(bytes_free);
       if (bytes_free < byte_count)
         return NetStatusFull;
     }
     tc_memcpy(to, output, byte_count);
     discard_write_buffer_bytes(byte_count);
     return NetStatusOk;
   }
   /// "Cycle" by pulling bytes from the input and pass them to the output.
   NetStatus pull_input(dword byte_count, dword & bytes_pulled, dword min_byte_count=1)
   {
      if (pdevice_sink)
        return  pull_input(pdevice_sink, byte_count, bytes_pulled);
      if (pmemory_sink)
        return pull_input(pmemory_sink, byte_count, bytes_pulled, min_byte_count);
      return NetStatusBadCallParms;
   }

   NetStatus toss_input(dword toss_count)
   {
     NetStatus s = NetStatusOk;

     DataSinkDevtype *_device_sink = pdevice_sink;
     DataSinkDevtype NullSink( null_sink_function,  0);
     attach_sink(&NullSink);
     dword bytes_tossed  = 0;
     while (bytes_tossed < toss_count && s==NetStatusOk)
     {
       dword _bytes_pulled;
       s = pull_input(toss_count-bytes_tossed,_bytes_pulled);
       if (s==NetStatusOk)
         bytes_tossed += _bytes_pulled;
     }
     attach_sink(_device_sink);
     return s;
  }

  /// Seek to the next logical element in the input stream
  ///   NetStatusnbsseof          - finished the frame
  ///    NetStatusNextsmb2Message  - we are at another smb2message and we've leftjustified if needed and pulled to guarantee header:command are contiguous and they fit
  ///    NetStatusFailed
  //NetStatus seek_input()
  //{
  //
  //}
  NetStatus flush()
  {
     dword buffered_byte_count=0;
     dword bytes_pulled;
     byte *pdata = peek_input(buffered_byte_count);
     if (buffered_byte_count ==0)
       return NetStatusOk;
     else     // Pulling exactly what is in the buffer will push that much oout the pipe
      return  pull_input(buffered_byte_count, bytes_pulled, buffered_byte_count);
  }

  /// "Cycle" by pulling bytes from the input and returning them instead of passing them to the output.
  NetStatus pull_input(byte *data, dword byte_count, dword &bytes_pulled, dword min_byte_count=1)
  {
     bytes_pulled =0;
     while (bytes_pulled < min_byte_count)
     {
       dword buffered_byte_count=0;
       byte *pdata = peek_input(buffered_byte_count);
       dword r = std::min (buffered_byte_count,byte_count);
       if (data && r)  tc_memcpy(data, pdata,r);
       if (r)
       {
         consume_input(r);
         bytes_pulled += r;
       }
       if (bytes_pulled  < min_byte_count)
       {
         dword sourced_byte_count;
         NetStatus status = data_sourcer->source_data(read_buffer_pointer(),std::min(byte_count,read_buffer_free()), sourced_byte_count);
         if (status != NetStatusOk)
           return status;
         write_pointer += sourced_byte_count;
       }
     }
     return NetStatusOk;
  }
  byte *peek_input()                                       { return read_buffer_pointer(); };
  byte *peek_input(dword & valid_byte_count)               { valid_byte_count = read_buffer_count(); return read_buffer_pointer(); }

//  RTSMB_CLI_SESSION       *session_pSession()              {  return  pStream->pSession; }
  smb2_iostream           *session_pStream()               {  return  pStream; }
  void                    session_pStream(smb2_iostream * _pStream) {  pStream = _pStream; }
  dword get_smb2_read_pointer() {return (smb2_read_pointer);}
private:
  smb2_iostream  *pStream;
  StreamBufferDataSource * data_sourcer;
  /// All read pointer updates go through here.
  //  updates input pointer, also advances nbss and smb2 seek pointers.
  void consume_input (dword byte_count)
  {
    nbss_read_pointer += byte_count;
    smb2_read_pointer += byte_count;
    read_pointer += byte_count;
    if (read_pointer == write_pointer) read_pointer = write_pointer=0;
  }
  byte *get_write_buffer_pointer(dword & byte_count) { byte_count=buffer_size-write_pointer; return buffer_base+write_pointer;}
  byte *write_buffer_pointer() { return buffer_base+write_pointer;}
  void discard_write_buffer_bytes(dword byte_count) { write_pointer+=byte_count;}


  byte *read_buffer_pointer() { return buffer_base+read_pointer;}
  dword read_buffer_free() {return buffer_size-read_pointer;}
  dword read_buffer_count() {return write_pointer-read_pointer;}
  DataSinkDevtype *pdevice_sink;
  MemoryDataSink  *pmemory_sink;

  // physical buffer charateristics
  dword buffer_size;
  byte *buffer_base;
  dword write_pointer;
  dword read_pointer;

  // logical view
  dword nbss_frame_size;
  dword smb2_frame_size;
  dword nbss_read_pointer;
  dword smb2_read_pointer;

  void _attach_buffer(byte *_buffer_base, dword _buffer_size, dword preload_count)
  {
   buffer_base=_buffer_base;buffer_size=_buffer_size;write_pointer=preload_count; read_pointer=0;
  // no logical view yet
   nbss_frame_size=smb2_frame_size=nbss_read_pointer=smb2_read_pointer=0;
  }
  void _attach_nbss (dword _nbss_frame_size)
  {
    cout_log(0) << "new nbs frame sized: " << _nbss_frame_size << endl;
    nbss_frame_size=_nbss_frame_size;
    smb2_frame_size=nbss_read_pointer=smb2_read_pointer=0;
  }

  NetStatus pull_input(DataSinkDevtype *_device_sink, dword byte_count, dword & bytes_sunk)
  {
     bytes_sunk = 0;
     do
     {
       dword buffered_byte_count=0;
       byte *pdata = peek_input(buffered_byte_count);
       if (buffered_byte_count==0)
       {
         dword sourced_byte_count=0;
         NetStatus status = data_sourcer->source_data(read_buffer_pointer(),std::min(byte_count,read_buffer_free()), sourced_byte_count);
         if (status != NetStatusOk)
           return status;
         write_pointer += sourced_byte_count;
         pdata = peek_input(buffered_byte_count);
         if (!buffered_byte_count)
         {
           return status;
         }
       }
       dword this_bytes_sunk=0;
       NetStatus r = _device_sink->sink_bytes_to_device(pdata, std::min(byte_count,buffered_byte_count),this_bytes_sunk);
       if (r != NetStatusOk)
         return r;
       byte_count -= this_bytes_sunk;
       bytes_sunk += this_bytes_sunk;
//       read_pointer += this_bytes_sunk;
       consume_input(this_bytes_sunk);
 #warning do this
     }  while (byte_count);
     return NetStatusOk;
  }
  NetStatus pull_input(MemoryDataSink *_data_sink, dword byte_count, dword &bytes_pulled, dword min_byte_count=1)
  {
    bytes_pulled =0;
    while (bytes_pulled < min_byte_count)
    {
      dword buffered_byte_count=0;
      byte *pdata = peek_input(buffered_byte_count);
      if (buffered_byte_count==0)
      {
        dword sourced_byte_count=0;
        NetStatus status = data_sourcer->source_data(read_buffer_pointer(),std::min(byte_count,read_buffer_free()), sourced_byte_count);
        if (status != NetStatusOk)
          return status;
         write_pointer += sourced_byte_count;
        pdata = peek_input(buffered_byte_count);
        if (!buffered_byte_count)
        {
          return status;
        }
      }
      dword r = std::min (buffered_byte_count,byte_count);
      dword bytes_sunk=0;
      if (r)
      {
        NetStatus status = _data_sink->sink_data(pdata, r, bytes_sunk);
        if (status != NetStatusOk)
          return status;
      }
//       if (data && r)  tc_memcpy(data, pdata,r);
       consume_input(bytes_sunk);
       bytes_pulled += r;
     }
     return NetStatusOk;
  }

};

Smb2Session *smb2_reply_buffer_to_session(NetStreamBuffer &ReplyBuffer);

inline int rtsmb_cli_wire_smb2_iostream_flush_sendbuffer(NetStreamBuffer &SendBuffer)
{
    dword valid_byte_count;
    Smb2Session *pSmb2Session = smb2_reply_buffer_to_session(SendBuffer);

    TURN_ON (SendBuffer.session_pStream()->pBuffer->flags, INFO_CAN_TIMEOUT);


    if (pSmb2Session->pSession()->wire.state == CONNECTED)
    {
        SendBuffer.session_pStream()->pBuffer->state = WAITING_ON_US;
    }
    else
    {
        SendBuffer.session_pStream()->pBuffer->end_time_base = rtp_get_system_msec ();
        if (SendBuffer.flush() != NetStatusOk)
        {
            return -2;
        }
        SendBuffer.session_pStream()->pBuffer->state = WAITING_ON_SERVER;
    }
    return 0;
}


/// Flush the content of a sendbuffer to the network and then turn the direction of the buffer around to wait for a timneout or for a reply to the message ID.
inline int rtsmb_cli_wire_smb2_iostream_flush_sendbufferptr(NetStreamBuffer *SendBuffer)
{
    dword valid_byte_count;

    TURN_ON (SendBuffer->session_pStream()->pBuffer->flags, INFO_CAN_TIMEOUT);

    if (SendBuffer->session_pStream()->pSession->wire.state == CONNECTED)
//    if (pSession->state == CONNECTED)
    {
        SendBuffer->session_pStream()->pBuffer->state = WAITING_ON_US;
    }
    else
    {
        SendBuffer->session_pStream()->pBuffer->end_time_base = rtp_get_system_msec ();
        if (SendBuffer->flush() != NetStatusOk)
        {
            return -2;
        }
        SendBuffer->session_pStream()->pBuffer->state = WAITING_ON_SERVER;
    }
    return 0;
}

#endif // include_netstreambuffer
