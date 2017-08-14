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
   return (int)rtsmb2_net_write( ((struct SocketContext *)devContext)->socket, pData,size);
}

/// device for sourcing bytes from tcp stream.
inline int socket_source_function(void *devContext, byte *pData, int size)
{
   int r = rtsmb2_net_read ( ((struct SocketContext *)devContext)->socket, pData, size, size);
   return r;
}


typedef int (* pDeviceSendFn_t) (void *devContext, byte *pData, int size);
/// Attach this to NetStreamBuffer to sink streamdata to a device
class DataSinkDevtype {
public:
  DataSinkDevtype() {}
  /// Constructor assigns a send function and a device context for the send function.
  DataSinkDevtype(pDeviceSendFn_t _DeviceSendFn,void *_DeviceContext) {DeviceSendFn=_DeviceSendFn;DeviceContext= _DeviceContext;}

  void AssignSendFunction(pDeviceSendFn_t _DeviceSendFn,void *_DeviceContext) {DeviceSendFn=_DeviceSendFn;DeviceContext= _DeviceContext;}


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

class NetStreamOutputBuffer     {
public:
   NetStreamOutputBuffer()                              {};
   ~NetStreamOutputBuffer()                             {};
  void attach_buffer(byte *data, dword byte_count){ buffer_base=data; buffer_size=byte_count; bytes_buffered = 0;}
  byte *output_buffer_address(dword &bytes_available_for_sending)
  {
    bytes_available_for_sending = buffer_size-bytes_buffered;
    return buffer_base+bytes_buffered;
  }
  NetStatus push_to_buffer(byte *output, dword byte_count)
  {
     dword bytes_available_for_sending;
     byte *to = output_buffer_address(bytes_available_for_sending);
     memcpy(to, output, byte_count);
     bytes_buffered += byte_count;
     return NetStatusOk;
  }
  NetStatus push_output()
  {
    if (bytes_buffered == 0 || SmbSocket->send(buffer_base, bytes_buffered) == bytes_buffered)
    {
        bytes_buffered = 0;
        return NetStatusOk;
    }
    else
        return NetStatusDeviceSendFailed;
  }
  void attach_socket(SmbSocket_c  &_SmbSocket) {SmbSocket = &_SmbSocket; };
  int stream_session_wire_state;
  int stream_buffer_flags;
  int stream_buffer_state;
  dword stream_buffer_end_time_base;
  ddword stream_buffer_mid;
private:
  SmbSocket_c  *SmbSocket;
  byte *buffer_base;
  dword buffer_size;
  dword bytes_buffered;
};

/// Stream abstraction with buffering and installable data source and sinks
class NetStreamBuffer     {
public:
   NetStreamBuffer()                              {   pdevice_sink=0;pmemory_sink=0; data_sourcer=0; };
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

   /// Get location and number of bytes in the input buffer
   byte *buffered_data_pointer(dword &bytes_ready) { bytes_ready = buffered_count(); return buffered_data_pointer();}
   byte *buffered_data_pointer() { return buffer_base+write_pointer;}
   dword buffered_count() {return input_pointer-write_pointer;}

   // Push data to the output buuffer, flush first if necessary too make room
   NetStatus push_to_buffer(byte *output, dword byte_count)
   {
     NetStatus r = make_room_in_buffer_out(byte_count);
     if (r != NetStatusOk)
       return r;
     dword bytes_free;
     byte *to= get_write_buffer_pointer(bytes_free);
     if (bytes_free < byte_count)
         return NetStatusFull;
     memcpy(to, output, byte_count);
     discard_write_buffer_bytes(byte_count);
     return NetStatusOk;
   }

   // Pull data to the input buffer, if it can't fit copy the already processed data in the buffer down first
   NetStatus pull_new_nbss_frame(dword byte_count, dword & bytes_pulled, dword min_byte_count=1)
   {
     empty();
     NetStatus r = NetStatusDeviceRecvFailed;
     dword sourced_byte_count=0;
     if (data_sourcer)
        r = data_sourcer->source_data(input_buffer_pointer(),byte_count, sourced_byte_count);
     if (r == NetStatusOk)
        bytes_pulled = sourced_byte_count;
     else
        bytes_pulled = 0;
      advance_input_buffer_bytes(bytes_pulled);
      return r;
   }
   // Pull data to the input buffer, if it can't fit copy the already processed data in the buffer down first
   NetStatus purge_socket_input(dword byte_count)
   {
     empty();
     if (!data_sourcer)
       return NetStatusOk;
     while(byte_count)
     {
       dword sourced_byte_count=0;
       NetStatus r = NetStatusOk;
       r = data_sourcer->source_data(input_buffer_pointer(),byte_count, sourced_byte_count);
       if (r == NetStatusOk)
         byte_count -= sourced_byte_count;
       else
         return r;
       empty();
     }
     return NetStatusOk;
   }

   /// "Cycle" by pulling bytes from the input and returning them instead of passing them to the output.
   NetStatus pull_input(byte *data, dword byte_count, dword &bytes_pulled, dword min_byte_count=1)
   {
     bytes_pulled =0;
     cout_log(LL_JUNK)  << "pulling top count: " << byte_count << endl;

     while (bytes_pulled < min_byte_count)
     {
       dword buffered_byte_count=0;
       byte *pdata = peek_input(buffered_byte_count);
       cout_log(LL_JUNK)  << "buffered_byte_counts: " << buffered_byte_count << endl;
       dword r = std::min (buffered_byte_count,byte_count);
       if (data && r)  tc_memcpy(data, pdata,r);
       if (r)
       {
         consume_input(r);
         cout_log(LL_JUNK)  << "pulled r new bytes to app: " << r << endl;
         bytes_pulled += r;
       }
       if (bytes_pulled  < min_byte_count)
       {
         dword sourced_byte_count;
         NetStatus status = data_sourcer->source_data(input_buffer_pointer(),std::min(byte_count,input_buffer_free()), sourced_byte_count);
         if (status != NetStatusOk)
           return status;
         cout_log(LL_JUNK)  << "pulled n new bytes: " << sourced_byte_count << endl;
         write_pointer += sourced_byte_count;
       }

     }
     return NetStatusOk;
  }

  NetStatus flush()
  {
    return make_room_in_buffer_out(buffer_size+1);
  }

  byte *peek_input()                                       { return input_buffer_pointer(); };
  byte *peek_input(dword & valid_byte_count)               { valid_byte_count = input_buffer_count(); return input_buffer_pointer(); }

  dword get_smb2_read_pointer() {return (smb2_read_pointer);}

  int stream_session_wire_state;
  int stream_buffer_flags;
  int stream_buffer_state;
  dword stream_buffer_end_time_base;
  ddword stream_buffer_mid;
private:
  StreamBufferDataSource * data_sourcer;
  DataSinkDevtype *pdevice_sink;
  MemoryDataSink  *pmemory_sink;

  // physical buffer charateristics
  dword buffer_size;
  byte *buffer_base;
  dword write_pointer;
  dword input_pointer;
  // logical view
  dword nbss_frame_size;
  dword smb2_frame_size;
  dword nbss_read_pointer;
  dword smb2_read_pointer;


  void empty() { write_pointer=input_pointer=0; }

  /// Flush data out if needed to make room for more in the output buffer
  NetStatus make_room_in_buffer_out(dword byte_count)
  {
    dword free_count=0;
    byte *pfreedata = get_write_buffer_pointer(free_count);
    if (byte_count > free_count)
    {
      dword this_bytes_sunk=0;
      dword valid_byte_count=0;
      byte *psenddata = peek_input(valid_byte_count);
      NetStatus r = NetStatusOk;
      if (pdevice_sink)
         r = pdevice_sink->sink_bytes_to_device(psenddata, valid_byte_count,this_bytes_sunk);
      else if (pmemory_sink)
         r = pmemory_sink->sink_data(psenddata, valid_byte_count,this_bytes_sunk);
      if (r != NetStatusOk)
       return r;
      consume_input (this_bytes_sunk);
    }
    return NetStatusOk;
  }


  byte *outut_buffer_pointer() { return buffer_base+write_pointer;}
  dword output_buffer_free()   {return buffer_size-write_pointer;}

  ///
  byte *input_buffer_pointer() { return buffer_base+input_pointer;}
  dword input_buffer_free() {return buffer_size-input_pointer;}
  dword input_buffer_count() {return write_pointer-input_pointer;}


  /// All read pointer updates go through here.
  //  updates input pointer, also advances nbss and smb2 seek pointers.
  void consume_input (dword byte_count)
  {
    nbss_read_pointer += byte_count;
    smb2_read_pointer += byte_count;
    input_pointer += byte_count;
    if (input_pointer == write_pointer) input_pointer = write_pointer=0;
  }
  byte *get_write_buffer_pointer(dword & byte_count) { byte_count=buffer_size-write_pointer; return buffer_base+write_pointer;}
  byte *write_buffer_pointer() { return buffer_base+write_pointer;}
  void discard_write_buffer_bytes(dword byte_count) { write_pointer+=byte_count;}
  void advance_input_buffer_bytes(dword byte_count) {input_pointer+=byte_count;} ;




  void _attach_buffer(byte *_buffer_base, dword _buffer_size, dword preload_count)
  {
   buffer_base=_buffer_base;buffer_size=_buffer_size;write_pointer=preload_count; input_pointer=0;
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
         NetStatus status = data_sourcer->source_data(input_buffer_pointer(),std::min(byte_count,input_buffer_free()), sourced_byte_count);
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
// #warning do this
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
        NetStatus status = data_sourcer->source_data(input_buffer_pointer(),std::min(byte_count,input_buffer_free()), sourced_byte_count);
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
//       if (data && r)  memcpy(data, pdata,r);
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

    TURN_ON (SendBuffer.stream_buffer_flags, INFO_CAN_TIMEOUT);


    if (pSmb2Session->session_wire_state == CONNECTED)
    {
        SendBuffer.stream_buffer_state = WAITING_ON_US;
    }
    else
    {
        SendBuffer.stream_buffer_end_time_base = rtp_get_system_msec ();
        if (SendBuffer.flush() != NetStatusOk)
        {
            return -2;
        }
        SendBuffer.stream_buffer_state = WAITING_ON_SERVER;
    }
    return 0;
}


/// Flush the content of a sendbuffer to the network and then turn the direction of the buffer around to wait for a timneout or for a reply to the message ID.
inline int rtsmb_cli_wire_smb2_iostream_flush_sendbufferptr(NetStreamBuffer *SendBuffer)
{
    dword valid_byte_count;

    TURN_ON (SendBuffer->stream_buffer_flags, INFO_CAN_TIMEOUT);

    if (SendBuffer->stream_session_wire_state == CONNECTED)
//    if (pSession->state == CONNECTED)
    {
        SendBuffer->stream_buffer_state = WAITING_ON_US;
    }
    else
    {
        SendBuffer->stream_buffer_end_time_base = rtp_get_system_msec ();
        if (SendBuffer->flush() != NetStatusOk)
        {
            return -2;
        }
        SendBuffer->stream_buffer_state = WAITING_ON_SERVER;
    }
    return 0;
}

#endif // include_netstreambuffer
