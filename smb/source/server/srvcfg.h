#ifndef __SRV_CFG_H__
#define __SRV_CFG_H__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvnet.h"
#include "srvauth.h"
#include "smbnbds.h"
#include "srvssn.h"


/**
 * The maximum amount of sessions you want to be able to support simultaneously.
 *
 * Must be at least 1.
 *
 * You might increase this to allow more clients to connect to the server at once.
 * If the server is at maximum, new session requests will be denied.
 */
#define _CFG_RTSMB_MAX_SESSIONS              8


typedef struct _RTSMB_SERVER_CONTEXT
{
	/* CONFIGURATION PARAMETERS */
	unsigned short    max_threads;
	unsigned short    max_sessions;
	unsigned short    max_uids_per_session;
	unsigned short    max_fids_per_tree;
	unsigned short    max_fids_per_uid;
	unsigned short    max_fids_per_session;
	unsigned short    max_trees_per_session;
	unsigned short    max_searches_per_uid;
	unsigned short    max_shares;
	unsigned short    max_users;
	unsigned short    max_groups;
    unsigned long     max_smb2_transaction_size;
    unsigned short    max_smb1_transaction_size;
	unsigned long     max_smb2_frame_size;
	unsigned long     small_buffer_size;
	unsigned long     temp_buffer_size;
	unsigned long     in_buffer_size;
	unsigned long     out_buffer_size;
	unsigned long     big_buffer_size;
	unsigned short    num_big_buffers;
	int               enum_results_size;
	BBOOL             enum_results_in_use;
	int               server_table_size;
	int               domain_table_size;
    BBOOL             enable_oplocks;
	int               max_protocol;       // 1

	/* MUTEX HANDLES */
	unsigned long     bufsem;
	unsigned long     authsem;
	unsigned long     sharesem;
	unsigned long     printersem;
	unsigned long     cachesem;
	unsigned long     mailPDCNameSem;
	unsigned long     netsem;
	unsigned long    *activeSessions;
	unsigned long     enum_results_mutex;

	/* BUFFER POOLS */
	PFBYTE                      bigBuffers;
	PFCHAR                      bigBufferInUse;
	PNET_THREAD                 threads;
	PFCHAR                      threadsInUse;
    FID_T                       *fidBuffers;
    FIDOBJECT_T                 *fidObjectBuffers;
	PNET_SESSIONCTX             sessions;
	PFCHAR                      sessionsInUse;
	PFBYTE                      namesrvBuffer;
	PFBYTE                      client_buffer;
	PSR_RESOURCE                shareTable;
	PRTSMB_BROWSE_SERVER_INFO   enum_results;
	PRTSMB_BROWSE_SERVER_INFO   server_table;
	PRTSMB_BROWSE_SERVER_INFO   domain_table;

#if (HARDWIRE_NO_SHARED_SESSION_BUFFERS == 1) // Swap if we are using exclusive buffers
     byte *unshared_read_buffers [_CFG_RTSMB_MAX_SESSIONS];
     byte *unshared_write_buffers[_CFG_RTSMB_MAX_SESSIONS];
     byte *unshared_temp_buffers [_CFG_RTSMB_MAX_SESSIONS];
#endif

    /* Control diagnostics           */
    BBOOL                       display_login_info;
    BBOOL                       display_config_info;
	/* OTHER STUFF */
	byte              shareMode;
	short             guestAccount;
	GROUPS_T          groupList;
	USERLIST_T        userList;
	PFCHAR            local_master;
    PNET_THREAD       mainThread;
}
RTSMB_SERVER_CONTEXT;

typedef RTSMB_SERVER_CONTEXT *PRTSMB_SERVER_CONTEXT;

extern PRTSMB_SERVER_CONTEXT prtsmb_srv_ctx;

int rtsmb_server_config(void);

#endif /* INCLUDE_RTSMB_SERVER */

#endif
