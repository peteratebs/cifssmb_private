//
// smb2filio.cpp -
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

#include "smb2clientincludes.hpp"
#include "smb2filio.hpp"

bool SmbFilioWorker::seek(ddword offset, ddword &new_offset)
{
  return false;
}
int SmbFilioWorker::read(byte *buffer, int count)
{
  return false;
}
int SmbFilioWorker::write(byte *buffer, int count, bool dosync)
{
  return false;
}

bool SmbFilioWorker::send_read()
{
  int                 variable_content_size = 1;
  NetNbssHeader       OutNbssHeader;
  NetSmb2Header       OutSmb2Header;
  NetSmb2ReadCmd      Smb2ReadCmd;

diag_printf_fn(DIAG_DEBUG,"SmbFilioWorker::send_read() top filenumber This:%X session addr:%X %d\n",this,pSmb2Session,file_number);

  NetSmb2NBSSSendCmd<NetSmb2ReadCmd> Smb2NBSSCmd(SMB2_READ, pSmb2Session,OutNbssHeader,OutSmb2Header, Smb2ReadCmd, variable_content_size);
  OutSmb2Header.TreeId = pSmb2Session->Shares[share_number].tid;
  Smb2ReadCmd.StructureSize                 =  Smb2ReadCmd.FixedStructureSize();
  Smb2ReadCmd.Flags                         = 0;
  Smb2ReadCmd.Length                        = io_request_length;
  Smb2ReadCmd.Offset                        = io_request_offset;
  Smb2ReadCmd.FileId                        = pSmb2Session->Files[file_number].get_file_id();;
  Smb2ReadCmd.MinimumCount                  = 1; // io_request_length;
  Smb2ReadCmd.Channel                       = 0; // these are for 3.0
  Smb2ReadCmd.RemainingBytes                = 0; // may use as a hint for server readahead
  Smb2ReadCmd.ReadChannelInfoOffset         = 0; // these are for 3.0
  Smb2ReadCmd.ReadChannelInfoLength         = 0;
//  Smb2ReadCmd.Buffer                        = 0; // 2.10 just send
  byte zero[1];zero[0]=0;
  Smb2ReadCmd.copyto_variable_content(zero, 1);
  return Smb2NBSSCmd.flush();
}
int SmbFilioWorker::recv_read()
{
  dword in_variable_content_size = 0;
  dword bytes_pulled = 0;
  dword bytes_consumed = 0;
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  NetSmb2ReadReply    Smb2ReadReply;
  NetStatus r;
  int nread = 0; // return this through io_result if all goes well

  io_result = -1; // Assume failure to start
  r = pSmb2Session->RecvBuffer.pull_nbss_frame_checked("READ", Smb2ReadReply.PackedStructureSize(), bytes_pulled);
  if (r != NetStatusOk)
  {
      pSmb2Session->diag_text_warning("receive_read command failed pulling fixed part from the socket");
     return -1;
  }
  NetSmb2NBSSRecvReply<NetSmb2ReadReply> Smb2NBSSReply(SMB2_READ, pSmb2Session, InNbssHeader,InSmb2Header, Smb2ReadReply);


  if (Smb2ReadReply.DataOffset()!=0 && Smb2ReadReply.DataLength() != 0)  // If zero it means we are empty. Confused why recv hangs when I try to read all bytes on last message (including the 1 byte buff that is zero filled by the server)
  { // Skip to the content if we have to
    int t = (Smb2ReadReply.DataOffset()+InNbssHeader.FixedStructureSize())-bytes_pulled;  // Advance to the variable part if needed
    if (t>0)
    {
      pSmb2Session->diag_text_warning("receive_querydirectory content was offset ??");
      pSmb2Session->RecvBuffer.consume_bytes(t);
      bytes_pulled += t;
    }
    pSmb2Session->RecvBuffer.consume_bytes(bytes_pulled);
    dword nreadd = Smb2ReadReply.DataLength(); // return this through io_result if all goes well
    // read in the content which shouldl fit in our buffer.
    dword total_bytes_left = Smb2ReadReply.DataLength();
    total_bytes_left = (InNbssHeader.nbss_packet_size()+4)-bytes_pulled;

    if (total_bytes_left != nreadd)
    {
        pSmb2Session->diag_text_warning("receive_read command truncate bytes read from nbssview:%d to buff:%d",total_bytes_left, nreadd);
        total_bytes_left = nreadd;
    }
    dword bytes_ready;
    byte *pdata = pSmb2Session->RecvBuffer.buffered_data_pointer(bytes_ready);
    while (total_bytes_left)
    {
      dword payload_bytes_pulled = 0;
      if (pSmb2Session->RecvBuffer.pull_nbss_data(total_bytes_left,payload_bytes_pulled)!=NetStatusOk ||  payload_bytes_pulled==0)
      {
        pSmb2Session->diag_text_warning("receive_read command failed pulling variable part from the socket");
        return -1;
      }
      nread += payload_bytes_pulled;
      total_bytes_left     -= payload_bytes_pulled;
      bytes_pulled         += payload_bytes_pulled;
    }
    // return count,data in io_result,io_request_buffer
    io_result = nread;
    if (io_result > 0)
      memcpy(io_request_buffer, pdata, io_result);
   }
   pSmb2Session->diag_text_warning("receive_read command returned : %d bytes", io_result);
   return io_result;
}
bool SmbFilioWorker::send_write()
{
  int                 variable_content_size = io_request_length;
  NetNbssHeader       OutNbssHeader;
  NetSmb2Header       OutSmb2Header;
  NetSmb2WriteCmd     Smb2WriteCmd;

  NetSmb2NBSSSendCmd<NetSmb2WriteCmd> Smb2NBSSCmd(SMB2_WRITE, pSmb2Session,OutNbssHeader,OutSmb2Header, Smb2WriteCmd, variable_content_size);
  OutSmb2Header.TreeId                      = pSmb2Session->Shares[share_number].tid;
  Smb2WriteCmd.StructureSize                 =  Smb2WriteCmd.FixedStructureSize();
  Smb2WriteCmd.Length                        = io_request_length;
  Smb2WriteCmd.DataOffset                    = OutSmb2Header.FixedStructureSize() + Smb2WriteCmd.PackedStructureSize();
  Smb2WriteCmd.Offset                        = io_request_offset;
  Smb2WriteCmd.FileId                        = pSmb2Session->Files[file_number].get_file_id();;
  Smb2WriteCmd.Channel                       = 0; // these are for 3.0
  Smb2WriteCmd.RemainingBytes                = 0; // may use as a hint for server
  Smb2WriteCmd.WriteChannelInfoOffset        = 0; // these are for 3.0
  Smb2WriteCmd.WriteChannelInfoLength        = 0;
  Smb2WriteCmd.Flags                         = 0;

  Smb2WriteCmd.copyto_variable_content((void*)io_request_buffer, io_request_length);  // we have to do this

  // this should work
  return Smb2NBSSCmd.flush();
}
int SmbFilioWorker::recv_write()
{
  dword in_variable_content_size = 0;
  dword bytes_pulled = 0;
  dword bytes_consumed = 0;
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  NetSmb2WriteReply   Smb2WriteReply;
  NetStatus r;
  int nwritten = 0; // return this through io_result if all goes well

  io_result = -1; // Assume failure to start
  r = pSmb2Session->RecvBuffer.pull_nbss_frame_checked("WRITE", Smb2WriteReply.PackedStructureSize(), bytes_pulled);
  if (r != NetStatusOk)
  {
      pSmb2Session->diag_text_warning("receive_read write failed pulling fixed part from the socket");
     io_result = -1;
     return -1;
  }
  NetSmb2NBSSRecvReply<NetSmb2WriteReply> Smb2NBSSReply(SMB2_WRITE, pSmb2Session, InNbssHeader,InSmb2Header, Smb2WriteReply);
  io_result = Smb2WriteReply.Count(); // Assume failure to start
  return io_result;
}

bool SmbFilioWorker::send_flush()
{
  int                 variable_content_size = 0;
  NetNbssHeader       OutNbssHeader;
  NetSmb2Header       OutSmb2Header;
  NetSmb2FlushCmd     Smb2FlushCmd;

  NetSmb2NBSSSendCmd<NetSmb2FlushCmd> Smb2NBSSCmd(SMB2_FLUSH, pSmb2Session,OutNbssHeader,OutSmb2Header, Smb2FlushCmd, variable_content_size);
  OutSmb2Header.TreeId                      = pSmb2Session->Shares[share_number].tid;
  Smb2FlushCmd.StructureSize                = Smb2FlushCmd.FixedStructureSize();
  Smb2FlushCmd.FileId                       = pSmb2Session->Files[file_number].get_file_id();;
  // this should work
  return Smb2NBSSCmd.flush();
}
bool SmbFilioWorker::recv_flush()
{
  dword in_variable_content_size = 0;
  dword bytes_pulled=0;
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  NetSmb2FlushReply   Smb2FlushReply;
  NetStatus r;
  r = pSmb2Session->RecvBuffer.pull_nbss_frame_checked("FLUSH", Smb2FlushReply.PackedStructureSize(), bytes_pulled);
  if (r != NetStatusOk)
  {
      pSmb2Session->diag_text_warning("receive_flush failed pulling fixed part from the socket");
     return false;
  }
  NetSmb2NBSSRecvReply<NetSmb2FlushReply> Smb2NBSSReply(SMB2_FLUSH, pSmb2Session, InNbssHeader,InSmb2Header, Smb2FlushReply);
  return true;
}

extern int do_smb2_cli_writefile_worker(Smb2Session &Session,int share_number, int file_number, byte *buffer, ddword offset, int count, bool flush)
{
  SmbFilioWorker FilioWorker;
  FilioWorker.bindfileid(Session,share_number,file_number);
  FilioWorker.set_io_request_length(count);
  FilioWorker.set_io_request_offset(offset);
  FilioWorker.set_io_request_buffer(buffer);
  bool r = FilioWorker.send_write();
  if (r)
    return FilioWorker.recv_write();
  return -1;
}

extern int do_smb2_cli_readfile_worker(Smb2Session &Session,int share_number, int file_number, byte *buffer, ddword offset, int count)
{
  SmbFilioWorker FilioWorker;
//diag_printf_fn(DIAG_DEBUG,"do_smb2_read_from_file() top filenumber addr:%X %d\n",pSession,file_number);
  FilioWorker.bindfileid(Session,share_number,file_number);
  FilioWorker.set_io_request_length(count);
  FilioWorker.set_io_request_offset(offset);
  FilioWorker.set_io_request_buffer(buffer);
  bool r = FilioWorker.send_read();
  if (r)
    return FilioWorker.recv_read();
  else
    return -1;
}


extern bool do_smb2_cli_flush_worker(Smb2Session &Session,int share_number, int file_number)
{
  SmbFilioWorker FilioWorker;
  FilioWorker.bindfileid(Session,share_number,file_number);
  bool r = FilioWorker.send_flush();
  if (r)
    r = FilioWorker.recv_flush();
  return r;
}
