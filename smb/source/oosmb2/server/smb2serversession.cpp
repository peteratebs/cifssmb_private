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
  ReplyBuffer.attach_buffer(_p_reply_buffer_raw, _p_reply_buffer_size);

  sourcesockContext.socket = SmbSocket.socket();
  SocketSource.SourceFromDevice (socket_source_function, socket_drain_function, (void *)&sourcesockContext);
  ReplyBuffer.attach_source(SocketSource);

  sinksockContext.socket = SmbSocket.socket();
  SocketSink.AssignSendFunction(socket_sink_function, (void *)&sinksockContext);
  SendBuffer.attach_socket(SmbSocket);
  return true;
}

