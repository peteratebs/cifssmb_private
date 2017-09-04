//
// smb2filio.hpp -
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

#ifndef include_smb2filio
#define include_smb2filio

class SmbFilioWorker {
public:
  SmbFilioWorker()
  {
    io_request_offset = 0;
  }
  void bindfileid(Smb2Session &Smb2Session,int _share_number,int _file_number)
  {
    pSmb2Session =  &Smb2Session;
    share_number = _share_number;
    file_number  = _file_number;
    _p_smbclientFileId= (((dword)pSmb2Session->session_number()&0xffff)<<24) | (dword)share_number<<16 | (dword)file_number;
  }
  void bindfileid(dword smbclientFileid)
  {
    _p_smbclientFileId=smbclientFileid;
    pSmb2Session = FileIdToSession(smbclientFileid);     // Internal view of fileid
    share_number = FileIdToSharenumber(smbclientFileid);
    file_number  = FileIdToFilenumber(smbclientFileid);

  }
  void set_io_request_length(int _io_request_length) {io_request_length = _io_request_length;}
  void set_io_request_offset(ddword offset) {io_request_offset = offset;}
  void set_io_request_buffer(byte *_io_request_buffer) {io_request_buffer = _io_request_buffer;}

  bool seek (ddword offset, ddword &new_offset);
  int  read (byte *buffer, int count);
  int  write(byte *buffer, int count, bool dosync);

  bool send_read();
  int  recv_read();
  bool send_write();
  bool recv_write();
  bool send_flush();
  bool recv_flush();
private:
// Use these three methods to get to the underlying structure
//Smb2Session *FileIdToSession(Fileid)
//inline int   FileIdToSharenumber(Fileid)
//inline int   FileIdToFilenumber(Fileid)

  dword _p_smbclientFileId;                 // encode session:share:file
  Smb2Session *pSmb2Session;
  int share_number;
  int file_number;

  int   io_request_length;
  int   io_result;
  ddword io_request_offset;
  byte  *io_request_buffer;
};




#endif // include_smb2filion
