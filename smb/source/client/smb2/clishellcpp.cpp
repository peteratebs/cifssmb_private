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


#include "smb2clientincludes.hpp"

using namespace std;


class SmbShellWorker : private local_allocator,smb_diagnostics {
public:
  SmbShellWorker()
  {
    set_diag_level(DIAG_DEBUG); //(DIAG_INFORMATIONAL); // DIAG_DEBUG);
  }
  void go()
  {
    char *ip   = "192.168.1.2";
//    char *ip   = "192.168.1.12";
    byte mask[] = {255,255,255,0};

    ShellSession.set_connection_parameters(ip, mask, 445);
    ShellSession.set_user_parameters(
    #define DOLINUX   1
    #define DOWINDOWS 0
    #define DOEBS     0
     #if(DOLINUX)
     "peter",
     "542Lafayette",
     "WORKGROUP");
//     "vboxubuntu");
     #endif
     #if(DOWINDOWS)
     "peterv",
     "542Lafayette",
     "workgroup");
     #endif
     #if(DOEBS)
     "notebs",
     "notpassword",
     "domain");
     #endif
#if(DOEBS)
     ShellSession.set_share_parameters("\\\\SHARE0",0);
#endif
#if(DOLINUX)
   ShellSession.set_share_parameters("\\\\192.168.1.2\\peter",0);
#endif
    // Using a global accessor, may not need it anymore
    setCurrentActiveSession(&ShellSession);

    diag_printf(DIAG_INFORMATIONAL, "Call socket connect\n");

    if (ShellSession.connect_socket())
    {
      diag_printf(DIAG_INFORMATIONAL, "connect socket worked\ncalling connect server to establish a session with the user\n");
      if (ShellSession.connect_server())
      {
         diag_printf(DIAG_INFORMATIONAL, "connect user  worked\ncalling connect share\n");
         if (ShellSession.connect_share(0))
         {
           diag_printf(DIAG_INFORMATIONAL, "connect share worked\n");
           goconnected();
         }
      }
    }
   }
   void goconnected()
   {
     for (;;)
     {
       cout << "CMD>";
       cin >> current_command;
       if (current_command == "ls" || current_command == "LS")
       {
          word pat[32];
          pat[0] = (word)'*';
          pat[1] = 0;
          ShellSession.list_share(0,pat);
       }
       if (current_command == "quit" || current_command == "QUIT")
       {
         cout << "bye";
         break;
       }

     }
   }
private:
   string      current_command;
   Smb2Session ShellSession;
};

extern "C" int smb2_cli_shell()
{
    SmbShellWorker ShellWorker;

    ShellWorker.go();
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
    BothDirInfoIterator.FixedStructureAddress()+BothDirInfoIterator.PackedStructureSize()-1,
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
