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

// TODO - Unicode interface for username and password
// TODO - Convert NTLM to OO. It is not implemented in OO framework only spnego
// Session ids shares etc are not messhed. Implement treeconnect and create commands if server


bool Smb2ServerSession::connect_buffers() // private
{
  _p_send_buffer_size  = RTSMB_CFG_MAX_BUFFER_SIZE;
  _p_reply_buffer_size = RTSMB_CFG_MAX_BUFFER_SIZE;
  _p_send_buffer_raw = (byte *)smb_rtp_malloc(_p_send_buffer_size);
  _p_reply_buffer_raw = (byte *)smb_rtp_malloc(_p_reply_buffer_size);

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
  session_state = Session_State_Idle;
  rtsmb_util_guid(server_guid);
  server_max_transaction_size = 262144;
  server_global_caps = 0x04; // LARGE_MTU
  server_require_signing = false;
  client_capabilities = 0;
  resistered_users["notebs"] = "notpassword";
}

const word password_faked[] = {'n','o','t','p','a','s','s','w','o','r','d',0,};

const word *Smb2ServerSession::get_password_from_user_name( word *username, int &return_pwd_width_bytes)
{
//  user_to_password_unicode["notebs"] = rtsmb_util_malloc_ascii_to_unicode ("notpassword");
      return_pwd_width_bytes= sizeof(password_faked);
  return  password_faked;
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

  glSession.AttachLegacyBuffers((byte *)read_origin, size, (byte *)write_origin, write_size);

  switch (InSmb2Header.Command()) {
   case SMB2_NEGOTIATE          :
     return glSession.ProcessNegotiate();
     break;
   case SMB2_SESSION_SETUP      :
     return glSession.ProcessSetup();
     break;
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
    return glSession.ProcessEcho();
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

int  Smb2ServerSession::ProcessEcho()
{
  byte *nbss_read_origin= (byte *) read_origin;
  nbss_read_origin -= 4; // Look at the NBSS header
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  InNbssHeader.bindpointers(nbss_read_origin);
  InSmb2Header.bindpointers(nbss_read_origin+InNbssHeader.FixedStructureSize());
  NetSmb2EchoCmd Smb2EchoCmd;
  Smb2EchoCmd.bindpointers(nbss_read_origin+InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize());
  NetNbssHeader       OutNbssHeader;
  NetSmb2Header       OutSmb2Header;
  NetSmb2EchoReply     Smb2EchoReply;
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
