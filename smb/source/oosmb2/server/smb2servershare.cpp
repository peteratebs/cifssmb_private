//
// smbservershare.pp -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2017
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//  SMB2 client session level interface
//

#include "smb2serverincludes.hpp"
#include "smb2spnego.hpp"

Smb2ServerShareStruct server_share_table_core[RTSMB_CFG_MAX_SHARES];
static Smb2ServerShareStruct *map_available_share();

//  static Smb2ServerShare *map_available_share(int &share_handle);
// Smb2ServerShare server_share_table_core[RTSMB_CFG_MAX_SHARES];
// std::vector<Smb2ServerShare&> server_share_table;
// static Smb2ServerShare *map_available_share(int &share_handle);

extern void initialize_sharetable()
{
  memset(server_share_table_core, 0, sizeof(server_share_table_core));
}

/// Used by server side API to add a share by name sharetype is DISK 1,  _PRINTER 3,  IPC, 2
// extern Smb2ServerShare *add_sharename_to_sharetable(char *sharename_ascii, char *sharepath_ascii, int share_type, bool readonly)
extern Smb2ServerShareStruct *add_sharename_to_sharetable(char *sharename_ascii, char *sharepath_ascii, int share_type, bool readonly)
{
  int share_handle;
  Smb2ServerShareStruct *ServerShare = map_available_share();
//  Smb2ServerShare *ServerShare = map_available_share(share_handle);
  if (ServerShare)
  {
    ServerShare->share_type                = share_type;
    ServerShare->is_readonly               = readonly;
    ServerShare->alloced_sharename_unicode = rtsmb_util_malloc_ascii_to_unicode(sharename_ascii);
    ServerShare->alloced_sharename_ascii   = rtsmb_util_malloc_ascii_to_ascii(sharename_ascii);
    ServerShare->alloced_sharepath_ascii   = rtsmb_util_malloc_ascii_to_ascii(sharepath_ascii);
  }
  return ServerShare;
}


/// Used by network command handler to find a share by SID
// extern Smb2ServerShare
Smb2ServerShareStruct *map_shareid_to_sharehandle(dword share_id)
{
  for (int i = 0; i < RTSMB_CFG_MAX_SHARES; i++)
    if (server_share_table_core[i].is_currently_inuse&&server_share_table_core[i].share_id==share_id)
       return &server_share_table_core[i];
  return 0;
}
/// Used by network command handler to find a share name by its name
extern Smb2ServerShareStruct *map_sharename_to_sharehandle(word *sharename_unicode, int sharename_length)
{
   for (int i = 0; i < RTSMB_CFG_MAX_SHARES; i++) {
    if (server_share_table_core[i].is_currently_inuse)
    {
       if (rtsmb_util_unicode_strnicmp(sharename_unicode,server_share_table_core[i].alloced_sharename_unicode,sharename_length)==0)
       {
         return &server_share_table_core[i];
       }
    }
  }
  return 0;
}

static Smb2ServerShareStruct *map_available_share()
{
 Smb2ServerShareStruct *pResult = 0;
 for (int i = 0; i < RTSMB_CFG_MAX_SHARES; i++)
 {
    if (server_share_table_core[i].is_currently_inuse==false)
    {
      pResult = &server_share_table_core[i];
      pResult->share_handle = i;
      pResult->share_id = i+0x4000;
      pResult->is_currently_inuse = true;
      break;
    }
 }
 return pResult;
}

void Smb2ServerShare::Clear()
{
cout << "Smb2ServerShare::Clear() handle ??:" << share_handle <<  endl;
   if (alloced_sharename_unicode) smb_rtp_free(alloced_sharename_unicode);
   if (alloced_sharename_ascii)   smb_rtp_free(alloced_sharename_ascii);
   if (alloced_sharepath_ascii)   smb_rtp_free(alloced_sharepath_ascii);
   alloced_sharename_unicode = 0;
   alloced_sharename_ascii   = 0;
   alloced_sharepath_ascii   = 0;
   share_type                = 0;     //     DISK 1,  _PRINTER 3,  IPC, 2
   share_flags               = 0; //     SMB2_FPP_ACCESS_MASK_FILE_READ_DATA et al
   is_currently_cwd          = false;
   is_currently_inuse        = false;
   is_readonly               = false;
}


Smb2ServerShare::Smb2ServerShare()
{
   alloced_sharename_unicode = 0;
   alloced_sharename_ascii   = 0;
   alloced_sharepath_ascii   = 0;
cout << "Smb2ServerShare::Smb2ServerShare()" << endl;
   Clear();
}
Smb2ServerShare::~Smb2ServerShare()
{
cout << "~Smb2ServerShare::Smb2ServerShare()" << endl;
   Clear();
}
