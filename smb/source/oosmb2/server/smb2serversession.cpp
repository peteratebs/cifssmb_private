//
// session.cpp -
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

#include "smb2serverincludes.hpp"

extern "C" void call_me_server()
{
  Smb2ServerSession ServerSession;
  NetNbssHeader       OutNbssHeader;
  NetSmb2Header       OutSmb2Header;
  NetSmb2NegotiateReply Smb2NegotiateReply;
  dword variable_size=0;
  NetSmb2NBSSServerSendReply<NetSmb2NegotiateReply> Smb2NBSSReply((word)SMB2_NEGOTIATE, &ServerSession, OutNbssHeader, OutSmb2Header,  Smb2NegotiateReply, variable_size);
  return;
}

bool Smb2ServerSession::connect_buffers() // private
{
  _p_send_buffer_size  = RTSMB_CFG_MAX_BUFFER_SIZE;
  _p_reply_buffer_size = RTSMB_CFG_MAX_BUFFER_SIZE;
  _p_send_buffer_raw = (byte *)rtp_malloc(_p_send_buffer_size);
  _p_reply_buffer_raw = (byte *)rtp_malloc(_p_reply_buffer_size);


  SendBuffer.attach_buffer(_p_send_buffer_raw, _p_send_buffer_size);
  RecvBuffer.attach_buffer(_p_reply_buffer_raw, _p_reply_buffer_size);

  sourcesockContext.socket = SmbSocket.socket();
  SocketSource.SourceFromDevice (socket_source_function, socket_drain_function, (void *)&sourcesockContext);
  RecvBuffer.attach_source(SocketSource);

  sinksockContext.socket = SmbSocket.socket();
  SocketSink.AssignSendFunction(socket_sink_function, (void *)&sinksockContext);
  SendBuffer.attach_socket(SmbSocket);
  return true;
}



Smb2ServerSession::Smb2ServerSession()
{
  rtsmb_util_guid(server_guid);
  server_max_transaction_size = 262144;
  server_global_caps = 0x04; // LARGE_MTU
  server_require_signing = false;
  client_capabilities = 0;
}
void Smb2ServerSession::AttachLegacyBuffers(byte *_read_origin, dword _read_size, byte *_write_origin, dword _write_size)
{
  read_origin = _read_origin;
  read_size   = _read_size;
  write_origin= _write_origin;
  write_size  = _write_size;
}


Smb2ServerSession glSession;

extern "C" int FuckWithSmb2OO(void *read_origin, dword size, void *write_origin, dword write_size)
{
  byte *nbss_read_origin= (byte *) read_origin;
  nbss_read_origin -= 4; // Look at the NBSS header
  diag_printf_fn(DIAG_INFORMATIONAL,"FuckWithSmb2OO size is: %d\n", size);
  diag_printf_fn(DIAG_INFORMATIONAL,"FuckWithSmb2OO is: %X %d\n", read_origin,size);

  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;

  InNbssHeader.bindpointers(nbss_read_origin);
  InSmb2Header.bindpointers(nbss_read_origin+InNbssHeader.FixedStructureSize());

  InNbssHeader.show_contents();
  InSmb2Header.show_contents();

  if (InSmb2Header.Command()==SMB2_NEGOTIATE)
  {
    diag_printf_fn(DIAG_INFORMATIONAL,"FuckWithSmb2OO processs negotiate\n");
    glSession.AttachLegacyBuffers((byte *)read_origin, size, (byte *)write_origin, write_size);
    return glSession.ProcessNegotiate();
  }

  switch (InSmb2Header.Command()) {
   case SMB2_NEGOTIATE          :
   {
    diag_printf_fn(DIAG_INFORMATIONAL,"FuckWithSmb2OO processs negotiate\n");
    glSession.AttachLegacyBuffers((byte *)read_origin, size, (byte *)write_origin, write_size);
    return glSession.ProcessNegotiate();
   }
   break;
   case SMB2_SESSION_SETUP      :
   case SMB2_LOGOFF             :
   case SMB2_TREE_CONNECT       :
   case SMB2_TREE_DISCONNECT    :
   case SMB2_CREATE             :
   case SMB2_CLOSE              :
   case SMB2_FLUSH              :
   case SMB2_READ               :
   case SMB2_WRITE              :
   case SMB2_LOCK               :
   case SMB2_IOCTL              :
   case SMB2_CANCEL             :
     break;
   case SMB2_ECHO               :
   {
    NetSmb2EchoCmd Smb2EchoCmd;
    Smb2EchoCmd.bindpointers(nbss_read_origin+InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize());
    NetNbssHeader       OutNbssHeader;
    NetSmb2Header       OutSmb2Header;
    NetSmb2EchoCmd      Smb2EchoReply;
    byte *nbss_write_origin= (byte *) write_origin;
    nbss_write_origin-=4;
    memset(nbss_write_origin, 0,OutNbssHeader.FixedStructureSize()+OutSmb2Header.FixedStructureSize()+Smb2EchoReply.FixedStructureSize());
    OutNbssHeader.bindpointers(nbss_write_origin);
    OutSmb2Header.bindpointers(nbss_write_origin+OutNbssHeader.FixedStructureSize());
    Smb2EchoReply.bindpointers(nbss_write_origin+OutNbssHeader.FixedStructureSize()+OutSmb2Header.FixedStructureSize());

    OutSmb2Header.InitializeReply(InSmb2Header);
    OutNbssHeader.nbss_packet_size = OutSmb2Header.FixedStructureSize()+ Smb2EchoReply.FixedStructureSize();
    Smb2EchoReply.StructureSize = 4;

    diag_printf_fn(DIAG_INFORMATIONAL,"FuckWithSmb2OO RECVED echo: %d\n", Smb2EchoCmd.StructureSize());

    OutNbssHeader.show_contents();
    OutSmb2Header.show_contents();

    return OutNbssHeader.nbss_packet_size()+4;
   }
   break;
   case SMB2_QUERY_DIRECTORY    :
   case SMB2_CHANGE_NOTIFY      :
   case SMB2_QUERY_INFO         :
   case SMB2_SET_INFO           :
   case SMB2_OPLOCK_BREAK       :
     break;
  }
  return 0;
}
