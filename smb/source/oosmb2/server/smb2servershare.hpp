//
// smbservershare.hpp -
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

#ifndef include_smbservershare
#define include_smbservershare

typedef struct Smb2ServerShareStruct_s {
    int   share_type;     //     DISK 1,  _PRINTER 3,  IPC, 2
    int   share_flags;    //     SMB2_FPP_ACCESS_MASK_FILE_READ_DATA et al
    int   share_handle;   //     index into our share table
    dword share_id;       //     external shareid
    word  *alloced_sharename_unicode;
    char  *alloced_sharename_ascii;
    char  *alloced_sharepath_ascii;
    bool  is_readonly;
    bool is_currently_inuse;
    bool is_currently_cwd;
} Smb2ServerShareStruct;

class Smb2ServerShare : public smb_diagnostics {
public:
    Smb2ServerShare();
    ~Smb2ServerShare();
    void Clear();

    bool use_disk_share(char *pathname, bool readonly=false);
    bool use_disk_share(char *sharename, char *nativepathname, bool readonly=false);
    bool map_name_to_shareid(word *sharename_unicode, int sharename_length, dword &share_id);
    int   map_sharehandle_to_share_type(dword share_id);
    int   map_sharehandle_to_share_flags(dword share_id);
    dword map_sharehandle_to_maximal_access_flags(dword share_id);

    int   share_type;     //     DISK 1,  _PRINTER 3,  IPC, 2
    int   share_flags;    //     SMB2_FPP_ACCESS_MASK_FILE_READ_DATA et al
    int   share_handle;   //     index into our share table
    dword share_id;       //     external shareid
    word  *alloced_sharename_unicode;
    char  *alloced_sharename_ascii;
    char  *alloced_sharepath_ascii;
    bool  is_readonly;
    bool is_currently_inuse;
    bool is_currently_cwd;
//  private:
};

/// Called first by static initializer method
extern void initialize_sharetable();
/// Used by server side API to add a share by name sharetype is DISK 1,  _PRINTER 3,  IPC, 2;
extern Smb2ServerShareStruct *add_sharename_to_sharetable(char *sharename_ascii, char *sharepath_ascii, int share_type, bool readonly);
/// Used by network command handler to find a share by SID
extern Smb2ServerShareStruct *map_shareid_to_sharehandle(dword share_id);
/// Used by network command handler to find a share name by its name
extern Smb2ServerShareStruct *map_sharename_to_sharehandle(word *sharename_unicode, int sharename_length);

#endif // include_smb2session
