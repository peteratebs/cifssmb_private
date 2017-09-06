//
// smb2serverwireobjects.hpp -
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
#ifndef include_smb2serverwireobjects
#define include_smb2serverwireobjects

template <class T>
class NetSmb2NBSSRecvCmd {
public:
  NetSmb2NBSSRecvCmd(word command, Smb2ServerSession  *_pSmb2ServerSession, NetNbssHeader  &_nbss, NetSmb2Header   &_smb2,  T &_reply)
  {
    pSmb2ServerSession=_pSmb2ServerSession; nbss =&_nbss;   smb2 =&_smb2;  reply  =&_reply ;
    isvariable = false; base_address=0; variablesize=0;
    smb2_command = command;
    dword bytes_ready;
    byte *nbsshead =  pSmb2ServerSession->ReplyBuffer.buffered_data_pointer(bytes_ready);
    byte *nbsstail  = nbsshead+4;
    byte *cmdtail =   bindpointers(nbsshead);
  }
  // Cloned from NetWireStruct()
  int  FixedStructureSize()  { return nbss->FixedStructureSize() + smb2->FixedStructureSize() +  reply->FixedStructureSize();};
  void addto_variable_content(dword delta_variablesize) {variablesize += delta_variablesize;};
  void push_output(NetStreamOutputBuffer  &StreamBuffer)
  {
    StreamBuffer.add_to_buffer_count(objectsize+variablesize);
  }
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       byte *nbsshead = _raw_address; // Was this in earklier build. ReplyBuffer->session_wire_incoming_nbss_header;
       byte *nbsstail =nbss->bindpointers(nbsshead);
       byte *smbtail = smb2->bindpointers(nbsstail);
       byte *replytail = reply->bindpointers(smbtail);
       return _raw_address+FixedStructureSize();}
  byte *FixedStructureAddress() { return base_address; };

  private:
     T                     *reply;
     Smb2ServerSession           *pSmb2ServerSession;
     NetNbssHeader         *nbss;
     NetSmb2Header         *smb2;
     word                   smb2_command;
     byte *base_address;
     bool isvariable;
     dword objectsize;
     dword variablesize;
};




///    Template class for generating frames of nbssheader:smb2:<commandtype>
///      Template helps fills out the nbss and smb2 headers in the buffer and also helps send the buffer.
//       The specific cmd is exposed for populating
///   See _rtsmb2_cli_session_send_negotiate() for an example
///     Requires specific prolog usage in a funtions:
///      dword variable_content_size = (dword)2*sizeof(word);   optional arg defaults to zero
///      NetNbssHeader       OutNbssHeader;     Nsss and smb2 declarations are always the same
///      NetSmb2Header       OutSmb2Header;
///      NetSmb2NegotiateCmd Smb2NegotiateCmd;  The command to be templated.
///      NetSmb2NBSSServerSendReply<NetSmb2NegotiateCmd> Smb2NBSSCmd(SMB2_NEGOTIATE, SendBuffer,OutNbssHeader,OutSmb2Header, Smb2NegotiateCmd, variable_content_size);

bool checkSessionSigned();

template <class T>
class NetSmb2NBSSServerSendReply {
public:
//  int status;
  NetSmb2NBSSServerSendReply(word command, Smb2ServerSession  *_pSmb2ServerSession, NetNbssHeader  &_nbss, NetSmb2Header &_smb2,  T &_cmd, dword _variable_size=0)
  {
    pSmb2ServerSession = _pSmb2ServerSession; nbss =&_nbss;   smb2 =&_smb2;  cmd  =&_cmd ;
    isvariable = false; base_address=0; variablesize=_variable_size;
    smb2_command = command;

//    pSmb2ServerSession->prep_session_for_command(cmd->command_name(), cmd->command_id()); // Drain inp and output buffers to start a new command

    dword bytes_available_for_sending;
    byte *nbsshead = pSmb2ServerSession->SendBuffer.output_buffer_address(bytes_available_for_sending);
    byte *nbsstail  = nbsshead+4;
    byte *cmdtail = bindpointers(nbsshead);
    cmdtail  += _variable_size;   // Add in 2 variable words, not good

    nbss->nbss_packet_type = RTSMB_NBSS_COM_MESSAGE;
    nbss->nbss_packet_size = PDIFF(cmdtail,nbsstail);
#if(0)
    ddword SessionId = getCurrentActiveSession_session_id(); // getCurrentActiveSession()->session_server_info_smb2_session_id;
    if (smb2_command == SMB2_NEGOTIATE)
      pSmb2ServerSession->SendBuffer.stream_buffer_mid = pSmb2ServerSession->unconnected_message_id();
    else
      pSmb2ServerSession->SendBuffer.stream_buffer_mid = pSmb2ServerSession->next_message_id();
    smb2->Initialize(command,(ddword) pSmb2ServerSession->SendBuffer.stream_buffer_mid, SessionId);

    // Sign the message is signing is enabe and it should be signed (>= SMB2_TREE_CONNECT should be correct since we don't support encrypted voumes
    if (smb2_command >= SMB2_TREE_CONNECT && checkSessionSigned())
    {
       dword Flags = smb2->Flags();
       Flags += SMB2_FLAGS_SIGNED;
       smb2->Flags = Flags;
    }
#endif
    nbss->push_output(pSmb2ServerSession->SendBuffer);   // account for sizes in the buffer
    smb2->push_output(pSmb2ServerSession->SendBuffer);
  }
  bool flush()
  {
//    pSmb2ServerSession->update_timestamp();
    cmd->push_output(pSmb2ServerSession->SendBuffer);
    byte signature[16];
#if (0)
    if (checkSessionSigned())
    {
      size_t length=0;
      byte *signme = RangeRequiringSigning(length);
      calculate_smb2_signing_key((void *)pSmb2ServerSession->session_key(), (void *)signme, length, (unsigned char *)signature);
//     memset (signature, 0xaa , 16);
    }
    else
#endif
     memset (signature, 0 , 16);
    smb2->Signature = signature;

    bool r=true;
    NetStatus Status = pSmb2ServerSession->SendBuffer.flush_output();
    if (Status !=NetStatusOk)
    {
//      setSessionSocketError(pSmb2ServerSession , true, NetStatusDeviceSendFailed);
      pSmb2ServerSession->diag_text_warning("Socket error sending message:%d status:%d",smb2_command,Status);
      r=false;
    }
    return r;
  }
  // Cloned from NetWireStruct()
  int  FixedStructureSize()  { return nbss->FixedStructureSize() + smb2->FixedStructureSize() +  cmd->FixedStructureSize();}
  byte *RangeRequiringSigning(size_t &length)  { length = variablesize + smb2->FixedStructureSize()+cmd->PackedStructureSize();return smb2->FixedStructureAddress();}
  void addto_variable_content(dword delta_variablesize) {variablesize += delta_variablesize; };
  void push_output(NetStreamOutputBuffer  &StreamBuffer) { StreamBuffer.add_to_buffer_count(objectsize+variablesize); }
  unsigned char *bindpointers(byte *_raw_address) {
       memset(_raw_address, 0, FixedStructureSize()); // uninitialized fields default to zero
       base_address = _raw_address;
       byte *nbsshead = _raw_address;
       byte *nbsstail =nbss->bindpointers(nbsshead);
       byte *smbtail = smb2->bindpointers(nbsstail);
       byte *cmdtail = cmd->bindpointers(smbtail);
       return _raw_address+FixedStructureSize();}
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
  private:
     Smb2ServerSession            *pSmb2ServerSession;
     word                   smb2_command;
     T                      *cmd;
     NetNbssHeader          *nbss;
     NetSmb2Header          *smb2;
     byte *base_address;
     bool isvariable;
     dword objectsize;
     dword variablesize;
};

#endif // include_smb2serverwireobjects
