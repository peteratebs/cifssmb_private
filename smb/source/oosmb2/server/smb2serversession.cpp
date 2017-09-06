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


extern "C" int FuckWithSmb2OO(void *read_origin, dword size, void *write_origin, dword wrtite_size)
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

#define SMB2_ECHO               0x000D   // Smartpointer and handler  completed
  if (InSmb2Header.Command() == SMB2_ECHO)
  {
    NetSmb2EchoCmd Smb2EchoCmd;
    Smb2EchoCmd.bindpointers(nbss_read_origin+InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize());

    diag_printf_fn(DIAG_INFORMATIONAL,"FuckWithSmb2OO RECVED echo: %d\n", Smb2EchoCmd.StructureSize());
    strcpy((char *)write_origin, "Suck on this  Suck on this  Suck on this  Suck on this  Suck on this  Suck on this  ");
    return strlen("Suck on this  Suck on this  Suck on this  Suck on this  Suck on this  Suck on this  ");
  }
  return 0;
}
