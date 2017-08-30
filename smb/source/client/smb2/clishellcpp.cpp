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

std::vector<std::string> split(const std::string& text, const std::string& delims)
{
    std::vector<std::string> tokens;
    std::size_t start = text.find_first_not_of(delims), end = 0;

    while((end = text.find_first_of(delims, start)) != std::string::npos)
    {
        tokens.push_back(text.substr(start, end - start));
        start = text.find_first_not_of(delims, end);
    }
    if(start != std::string::npos)
        tokens.push_back(text.substr(start));

    return tokens;
}


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
      ShellSession.display_text_warnings();
      diag_printf(DIAG_INFORMATIONAL, "connect socket worked\ncalling connect server to establish a session with the user\n");
      if (ShellSession.connect_server())
      {
         ShellSession.display_text_warnings();
         diag_printf(DIAG_INFORMATIONAL, "connect user  worked\ncalling connect share\n");
         if (ShellSession.connect_share(0))
         {
           ShellSession.display_text_warnings();
           diag_printf(DIAG_INFORMATIONAL, "connect share worked\n");
           goconnected();
         }
      }
    }
    ShellSession.show_socket_errors(true);
    ShellSession.display_text_warnings();
   }
   void goconnected()
   {
     string delims(" ");
     for (;;)
     {
       char current_command_cstring[255];
       cout << "CMD>";
       std::cin.getline(current_command_cstring, 255);
       string current_command(current_command_cstring);
       std::vector<std::string> command_line = split(current_command, delims);
       if (command_line[0] == "ls" || command_line[0] == "LS")
       {
        char *path = "";
        char *pattern = "*";
          if (command_line.size() == 2)
          {
            path = (char *) command_line[1].c_str();
          }
          else if (command_line.size() == 3)
          {
            path = (char *) command_line[1].c_str();
            pattern = (char *) command_line[2].c_str();
          }
          dualstringdecl(pattern_string)    ;*pattern_string     = pattern;
          ShellSession.open_dir(0, 0 , path, false);             // open directory named share,file, path, read only
          ShellSession.list_share(0,0,pattern_string->utf16());  // do the ls
          ShellSession.close_dirent(0, 0);                       // close the directory we used
       }
       else if (command_line[0] == "mkdir" || command_line[0] == "MKDIR")
       {
        char *path = "";
        char *pattern = "*";
          if (command_line.size() == 2)
          {
            path = (char *) command_line[1].c_str();
          }
          if (ShellSession.make_dir(0, 1, path))
            ShellSession.close_dirent(0, 1);
       }
       else if (command_line[0] == "rmdir" || command_line[0] == "RMDIR")
       {
        char *path = "";
          if (command_line.size() == 2)
          {
            path = (char *) command_line[1].c_str();
          }
          ShellSession.delete_dir(0, path);
       }
       else if (command_line[0] == "mvdir" || command_line[0] == "MVDIR")
       {
          if (command_line.size() == 3)
          {
            char *frompath = (char *) command_line[1].c_str();
            char *topath = (char *) command_line[2].c_str();
            ShellSession.rename_dir(0, frompath, topath);
          }
       }
       else if (command_line[0] == "mv" || command_line[0] == "MV")
       {
        char *path = "";
          if (command_line.size() == 3)
          {
            char *frompath = (char *) command_line[1].c_str();
            char *topath = (char *) command_line[2].c_str();
            ShellSession.rename_file(0, frompath, topath);
          }
       }
       else if (command_line[0] == "rm" || command_line[0] == "RM")
       {
        char *path = "";
          if (command_line.size() == 2)
          {
            path = (char *) command_line[1].c_str();
            ShellSession.delete_file(0, path);
          }
       }
       else if (command_line[0] == "quit" || command_line[0] == "QUIT")
       {
         cout << "bye";
         break;
       }
       ShellSession.display_text_warnings();
       ShellSession.show_socket_errors(true);
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
extern int PassDirscanToShell(void *pBuffer)
{
  ms_FILE_ID_BOTH_DIR_INFORMATION  BothDirInfoIterator;

  BothDirInfoIterator.bindpointers((byte *)pBuffer);

  NEWRTSMB_CLI_SESSION_DSTAT mystat;
  NEWRTSMB_CLI_SESSION_DSTAT *pstat = &mystat;
  tc_memcpy (pstat->filename,
    BothDirInfoIterator.FixedStructureAddress()+BothDirInfoIterator.PackedStructureSize(),
    BothDirInfoIterator.FileNameLength());
   pstat->filename[BothDirInfoIterator.FileNameLength()/2]=0;
   pstat->fattributes = (unsigned short) BothDirInfoIterator.FileAttributes();    //    unsigned short fattributes;
   pstat->fatime64= BothDirInfoIterator.LastAccessTime();
   pstat->fatime64= BothDirInfoIterator.LastAccessTime();
   pstat->fwtime64= BothDirInfoIterator.LastWriteTime();
   pstat->fctime64= BothDirInfoIterator.CreationTime();
   pstat->fhtime64= BothDirInfoIterator.ChangeTime();
   pstat->fsize = (dword) BothDirInfoIterator.EndofFile();
//   DisplayDirscan(pstat);
   dualstringdecl(file_name);
  *file_name = (word *) pstat->filename;

  cout << file_name->ascii() << endl;
//  diag_dump_unicode_fn(DIAG_DEBUG, "Filename: ", pstat->filename, BothDirInfoIterator.FileNameLength());
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
