//
// clishellcpp.cpp -
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

#include "smb2defs.hpp"
#include "smb2socks.hpp"
#include "netstreambuffer.hpp"
#include "wireobjects.hpp"
#include "mswireobjects.hpp"
#include "session.hpp"



extern "C" int smb2_cli_shell()
{
    cout << "Godbye cruel world ;-)" << endl;
    return 0;
}
// Format the dstat in C++ with alignment independent classes and call back to the shell to display
extern int FormatDirscanToDstat(void *pBuffer)
{
  ms_FILE_ID_BOTH_DIR_INFORMATION  BothDirInfoIterator;

  BothDirInfoIterator.bindpointers((byte *)pBuffer);

  NEWRTSMB_CLI_SESSION_DSTAT mystat;
  NEWRTSMB_CLI_SESSION_DSTAT *pstat = &mystat;
  tc_memcpy (pstat->filename,
    BothDirInfoIterator.FixedStructureAddress()+BothDirInfoIterator.FixedStructureSize()-1,
    BothDirInfoIterator.FileNameLength());
   pstat->fattributes = (unsigned short) BothDirInfoIterator.FileAttributes();    //    unsigned short fattributes;
   pstat->fatime64= BothDirInfoIterator.LastAccessTime();
   pstat->fatime64= BothDirInfoIterator.LastAccessTime();
   pstat->fwtime64= BothDirInfoIterator.LastWriteTime();
   pstat->fctime64= BothDirInfoIterator.CreationTime();
   pstat->fhtime64= BothDirInfoIterator.ChangeTime();
   pstat->fsize = (dword) BothDirInfoIterator.EndofFile();
//   DisplayDirscan(pstat);
   return BothDirInfoIterator.NextEntryOffset();
}

typedef int (*lscbfn)(void *params);

extern "C" int smbclient_session();
extern "C" int do_connect_command(int session_id, byte *ip_addres, byte *ip_mask, int portnumber);
extern "C" int do_disconnect_command(int session_id);
extern "C" int do_logon_command(int session_id, char *username, char *password, char *domain);
extern "C" int do_logoff_command(int session_id);
extern "C" int do_share_command(int session_id, char *share);
extern "C" int do_noshare_command(int share_id);               // share_id == (session_id<<8|share)
extern "C" int do_ls_command(int share_id, byte *path, byte *pattern, lscbfn callbackFn);


int smbclient_session() {return -1;};
int do_connect_command(int session_id, byte *ip_addres, byte *ip_mask, int portnumber) {return -1;};
int do_disconnect_command(int session_id) {return -1;};
int do_logon_command(int session_id, char *username, char *password, char *domain) {return -1;};
int do_logoff_command(int session_id) {return -1;};
int do_share_command(int session_id, char *share) {return -1;};
int do_noshare_command(int share_id) {return -1;};               // share_id == (session_id<<8|share {return -1;})
int do_ls_command(int share_id, byte *path, byte *pattern, lscbfn callbackFn) {return -1;};

extern "C" int do_cpp_net_command(char *command) {return -1;};
