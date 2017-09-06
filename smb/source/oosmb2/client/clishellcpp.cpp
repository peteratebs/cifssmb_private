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
#include "smb2filio.hpp"
#include "smb2api.hpp"
#include "rtpfile.h"

using namespace std;

#define ECHO_TIME_PERIOD_SECONDS 60
// TimedInput()  works for linux and probably needs modication for other OS's
static void TimedInput(byte *buffer, int n_bytes, int tmo);

// split the strings and replace '!' with space
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
    for (int i=0; i < tokens.size(); i++)
      for (int j=0; j < tokens[i].size(); j++)
          if (tokens[i][j] == '!') tokens[i][j]= ' ';
    return tokens;
}
bool is_command_line(string &inputcmd, const char *isitcmd)
{
  for (size_t i=0; i < inputcmd.size(); i++) inputcmd[i] = toupper(inputcmd[i]);
//  std::transform(s_name.begin(), s_name.end(), s_name.begin(), toupper);
  string isitcmdstring(isitcmd);
  return (isitcmdstring == inputcmd);
}

bool filename_is_remote(string &filename)
{
 if (filename[0] == '>' ||  filename[0] == '<')
 {
   filename = filename.substr(1);
   return true;
 }
 return false;
}
#if(0) // not used, sill testing prinmitives so dont confuse things
class ShellFile {
public:
  ShellFile ( bool _issmbclientFile, string _filename) { filename=_filename; issmbclientFile=_issmbclientFile; isopen=false;
  isstdin = isstdout = false;
  if (_filename == "STDIN" || _filename == "stdin") isstdin = true;
  if (_filename == "STDOUT" || _filename == "stdout") isstdout = true;
  }
  bool open_file (bool iswrite=false, bool iscreate=false)
  {
    if (issmbclientFile)
    {
     bool r = smb2_file_open (smbclientFile, filename.c_str(), iswrite);
     if (!r)
      return false;
      _p_SmbFilioWorker.bindfileid(smbclientFile);
    }
    else if (isstdout || isstdin)
      ;
    else
    {
     int r = rtp_file_open (&rtpFile, filename.c_str(), iswrite?RTP_FILE_O_CREAT|RTP_FILE_O_TRUNC|RTP_FILE_O_RDWR:0, iscreate?RTP_FILE_S_IWRITE:RTP_FILE_S_IREAD);
     if (r < 0)
      return false;
    }
    return true;
  }
  bool flush_file(){return true;};
  bool close_file()
  {
    if (issmbclientFile)
     smb2_file_close(smbclientFile);
    else if (isstdin||isstdout)
      ;
    else  rtp_file_close(rtpFile);
    return true;
  };
  int read_from_file(byte *buffer, int n_bytes)
  {
    if (issmbclientFile)
    { return (int)smb2_file_read(smbclientFile, buffer, n_bytes); }
    if (isstdin)
    {
        std::cin.getline((char *)buffer, n_bytes);
        if (buffer[0]!=0)  buffer[strlen((char *)buffer)+1] = 0; buffer[strlen((char *)buffer)]='\n';
        return strlen((char*)buffer);
    }
    else  { return (int)rtp_file_read(rtpFile, buffer, n_bytes); }
    return 0;
  }
  int write_to_file(byte *buffer, int n_bytes)
  {
    if (issmbclientFile)
    { return (int)smb2_file_write(smbclientFile, buffer, n_bytes); }
    if (isstdout)
    {
      std::cout << (char *) buffer;
      return strlen((char *)buffer);
    }
    else
    { return (int)rtp_file_write(rtpFile, buffer, n_bytes); }
  }
private:
  string filename;
  bool isstdout;
  bool isstdin;
  bool issmbclientFile;
  bool isopen;
  RTP_HANDLE  rtpFile;
  dword smbclientFile;
  SmbFilioWorker _p_SmbFilioWorker;
};
#endif
Smb2Session ShellSession;

class SmbShellWorker : private local_allocator,smb_diagnostics {
public:
  SmbShellWorker()
  {
    set_diag_level(DIAG_DEBUG); //(DIAG_INFORMATIONAL); // DIAG_DEBUG);
  }
    #define DOLINUX   1
    #define DOWINDOWS 0
    #define DOEBS     0
  void go()
  {
#if(DOLINUX)
    char *ip   = "192.168.1.2";
#endif
#if(DOWINDOWS)
     char *ip   = "192.168.1.12";
#endif
#if(DOEBS)
    char *ip   = "192.168.1.2";
#endif
    byte mask[] = {255,255,255,0};

    ShellSession.set_connection_parameters(ip, mask, 445);
    ShellSession.set_user_parameters(
     #if(DOLINUX)
     "peter",
     "542Lafayette",
     "WORKGROUP");
//     "vboxubuntu");
     #endif
     #if(DOWINDOWS)
     "peterv",
     "542Lafayette",
     "LAPTOP-ROQPO0PB"); // "workgroup");
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
#if(DOWINDOWS)
     ShellSession.set_share_parameters("\\\\192.168.1.12\\0a_share_with_virtual_box",0);
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
       cout << "CMD>";std::cout.flush();
      // std::cin.getline(current_command_cstring, 255);
       TimedInput((byte *)&current_command_cstring[0], 255, ECHO_TIME_PERIOD_SECONDS);
       if (!current_command_cstring[0])
         continue;
       string current_command(current_command_cstring);
       // split the strings and replace '!' with space
       std::vector<std::string> command_line = split(current_command, delims);
       if (is_command_line(command_line[0], "LS"))
       {
        char *path = (char *) "";
        char *pattern = (char *) "*";
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
       else if (is_command_line(command_line[0], "MKDIR"))
       {
        char *path = (char *) "";
        char *pattern = "*";
          if (command_line.size() == 2)
          {
            path = (char *) command_line[1].c_str();
          }
          if (ShellSession.make_dir(0, 1, path))
            ShellSession.close_dirent(0, 1);
       }
       else if (is_command_line(command_line[0], "RMDIR"))
       {
        char *path = (char *) "";
          if (command_line.size() == 2)
          {
            path = (char *) command_line[1].c_str();
          }
          ShellSession.delete_dir(0, path);
       }
       else if (is_command_line(command_line[0], "MVDIR"))
       {
          if (command_line.size() == 3)
          {
            char *frompath = (char *) command_line[1].c_str();
            char *topath = (char *) command_line[2].c_str();
            ShellSession.rename_dir(0, frompath, topath);
          }
       }
       else if (is_command_line(command_line[0], "ECHO"))
       { // This is generated by the console driver every ECHO_TIME_PERIOD_SECONDS seconds so the server doesn't disconnect
         ShellSession.echo();
       }
       else if (is_command_line(command_line[0], "MV"))
       {
        char *path = (char *) "";
          if (command_line.size() == 3)
          {
            char *frompath = (char *) command_line[1].c_str();
            char *topath = (char *) command_line[2].c_str();
            ShellSession.rename_file(0, frompath, topath);
          }
       }
       else if (is_command_line(command_line[0], "RM"))
       {
        char *path = (char *) "";
          if (command_line.size() == 2)
          {
            path = (char *) command_line[1].c_str();
            ShellSession.delete_file(0, path);
          }
       }
       else if (is_command_line(command_line[0], "CP"))
       {
        char *path = (char *) "";
        char *destpath = (char *) "";
        char *pattern = (char *) "*";
        bool source_isremote=false;
        bool source_isfile=false;
        bool dest_isremote=false;
        bool dest_isfile=false;
         bool has_dest=false;
         if (command_line.size() >= 2)
         {
           source_isremote=filename_is_remote(command_line[1]); // strips off < too iof needed
           path = (char *) command_line[1].c_str();
         }
         if (command_line.size() >= 3)
         {
           dest_isremote=filename_is_remote(command_line[2]); // strips off < too iof needed
           destpath = (char *) command_line[2].c_str();
           has_dest = true;
         }

         bool sourcevalid=false;
         dword sourcefileid;
         RTP_HANDLE  sourcertpFile;
         bool destvalid=false;
         dword destfileid;
         RTP_HANDLE  destrtpFile;

         int sourcefileno=-1;
         int destfileno=-1;
         if (source_isremote)
         {
           source_isfile=false;
           if (ShellSession.allocate_fileid(sourcefileid, 0))
           {
             sourcefileno = (int)(sourcefileid&0xffff);
             if (ShellSession.open_file(0, sourcefileno , path, false)==true)
               sourcevalid=true;
           }
         }
         else
         {
            int r = rtp_file_open (&sourcertpFile, path, 0, 0);
            if (r >= 0)
            {
              source_isfile=true;
              source_isremote=false;
              sourcevalid=false;
            }
         }

         if (dest_isremote)
         {
           dest_isfile=false;
           if (ShellSession.allocate_fileid(destfileid, 0))
           {
             destfileno = (int)(destfileid&0xffff);
             if (ShellSession.open_file(0, destfileno , destpath, true)==true)
               destvalid=true;
           }
         }
         else
         {
            dest_isremote=false;
            int r = rtp_file_open (&destrtpFile, destpath, RTP_FILE_O_CREAT|RTP_FILE_O_TRUNC|RTP_FILE_O_RDWR,RTP_FILE_S_IWRITE);
            if (r >= 0)
            {
              dest_isfile=true;
              destvalid=false;
            }
         }

         ddword offset = 0;
         dword total_bytes_read = 0;
         int res=0;
         do
         {
           res=-1;
           byte buffer[130]; int count =128;
           if (source_isremote)
             res=ShellSession.read_from_file(0, sourcefileno,buffer, offset, count);
           else if (source_isfile)
             res = rtp_file_read(sourcertpFile, buffer, count);
           if (res >0)
           {
              offset += res;
              total_bytes_read += res;
              if (dest_isremote)
                res=ShellSession.write_to_file(0, destfileno,buffer, offset, count);
              else if (dest_isfile)
                res = rtp_file_write(destrtpFile, buffer, count);
              else
              {
                buffer[res]=0;// so we can print
                diag_printf(DIAG_INFORMATIONAL, "\n>:\n%s\n:\n", buffer);
              }
           }
         } while (res > 0);
         if (source_isremote)
         {
            ShellSession.close_dirent(0, sourcefileno);                       // close the directory we used
            ShellSession.release_fileid(sourcefileid);
         }
         else if (source_isfile)
         {
             rtp_file_close(sourcertpFile);
         }
         if (dest_isremote)
         {
            ShellSession.flush_file(0, destfileno);
            ShellSession.close_dirent(0, destfileno);                       // close the directory we used
            ShellSession.release_fileid(destfileid);
         }
         else if (dest_isfile)
         {
             rtp_file_close(destrtpFile);
         }
         diag_printf(DIAG_INFORMATIONAL, "Bytes copied:%d\n", total_bytes_read);
       }
//       else if (command_line[0] == "echo" || command_line[0] == "ECHO")
       else if (is_command_line(command_line[0], "ECHO"))
       {
        for (int i=0; i < command_line.size(); i++)
         cout << "I:" << i << ":" << command_line[i] << ":remote:" <<  filename_is_remote(command_line[i])<< ":" << command_line[i] << ":"  << endl;
       }
       else if (is_command_line(command_line[0], "QUIT"))
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
//   Smb2Session ShellSession;
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

#define STDIN_FILENO 0
// Waits for input onthe console for n seconds or return the word "ECHO".
// clipped from stack exchange
// this works for linux and probably needs modication for other OS's
static void TimedInput(byte *buffer, int n_bytes, int tmo)
{
    int n;
    //Below cin operation should be executed within stipulated period of time
    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(STDIN_FILENO, &readSet);
    struct timeval tv = {tmo, 0};  // 10 seconds, 0 microseconds;
    if (select(1, &readSet, NULL, NULL, &tv) < 0) perror("select");
    if (FD_ISSET(STDIN_FILENO, &readSet))
    {
     std::cin.getline((char *)buffer, n_bytes);
     buffer[strlen((char *)buffer)+1] = 0;
    }
    else
    {  strcpy((char *) buffer,"ECHO");}
}