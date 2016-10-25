//
// NBNSSTUBS.C -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2015
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// This file contains all the functions necessary to still function while excluding NBNS
// functionality like group join announcements and responding to NBNS queries.
// If this feature is enabled the makefile should be edited to exclude the /servernb and /commonnb directories

#include "smbdefs.h"

#if (HARDWIRE_EXCLUDE_NBNS==1)

#include "rtpchar.h"  /* _YI_ 9/24/2004 */
#include "rtpscnv.h"  /* _YI_ 9/24/2004 */
#include "rtpprint.h" /* _VM_ 12/27/2004 */

#include "srvnbns.h"
#include "srvnet.h"
#include "smbnb.h"
#include "srvrsrcs.h"
#include "srvutil.h"

#include "srvcfg.h"
#include "smbutil.h"
#include "smbnbns.h"
#include "smbpack.h"
#include "smbnet.h"
#include "smbnbds.h"
#include "srvrap.h"
#include "srvbrws.h"
#include "smbdebug.h"

#include "rtptime.h"
#include "rtpsignl.h"
#include "rtpscnv.h"


//============================================================================
//    IMPLEMENTATION PRIVATE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS
//============================================================================
#define NAME_TABLE_SIZE				20 /* _YI_ */
#define NAME_CACHE_SIZE				2 /* only needed for master browser lookups and our server-client right now */
#define NAME_QUERY_SIZE				NAME_CACHE_SIZE

#define NB_FLAGS_BNODE	(0)
#define NB_FLAGS_PNODE	(0x2000)
#define NB_FLAGS_MNODE	(0x4000)
#define NB_FLAGS_GROUP	(0x8000)

typedef enum
{
	NS_NONAME = 0,
	NS_PENDING,
	NS_REGISTERED
} NBS_NAMESTATE_T;

//============================================================================
//    IMPLEMENTATION PRIVATE STRUCTURES
//============================================================================

typedef struct
{
	char name[RTSMB_NB_NAME_SIZE+1];	// space-filled
	BBOOL group;
	BBOOL announce;
	NBS_NAMESTATE_T status;
	word transID;
	int numSent;
	unsigned long nextSendBase;

} NBS_NAME_TABLE_ENTRY_T;
typedef NBS_NAME_TABLE_ENTRY_T RTSMB_FAR *PNBS_NAME_TABLE_ENTRY;

typedef struct
{
	BBOOL inUse;
	char name[RTSMB_NB_NAME_SIZE+1];	// space-filled
	byte ip [4];

} NBS_NAME_CACHE_ENTRY_T;
typedef NBS_NAME_CACHE_ENTRY_T RTSMB_FAR *PNBS_NAME_CACHE_ENTRY;

typedef struct
{
	BBOOL inUse;
	char name[RTSMB_NB_NAME_SIZE+1];	// space-filled
	int numQueries;
	unsigned long endTimeBase;

} NBS_NAME_QUERY_ENTRY_T;
typedef NBS_NAME_QUERY_ENTRY_T RTSMB_FAR *PNBS_NAME_QUERY_ENTRY;


//============================================================================
//    IMPLEMENTATION REQUIRED EXTERNAL REFERENCES (AVOID)
//============================================================================
//============================================================================
//    IMPLEMENTATION PRIVATE DATA
//============================================================================
RTSMB_STATIC NBS_NAME_TABLE_ENTRY_T nameTable[NAME_TABLE_SIZE];	// our own names

RTSMB_STATIC NBS_NAME_CACHE_ENTRY_T nameCache[NAME_CACHE_SIZE];	// names of others
RTSMB_STATIC int lastCacheIndex;	// last inserted cache index

RTSMB_STATIC NBS_NAME_QUERY_ENTRY_T nameQueryTable[NAME_QUERY_SIZE];	// names waiting to be queried
RTSMB_STATIC int lastQueryIndex;	// last inserted query index
RTSMB_STATIC unsigned long nameQueryTableSem;

//============================================================================
//    INTERFACE DATA
//============================================================================
char ns_groupName[RTSMB_NB_NAME_SIZE+1];		// space appended name
char ns_groupNameAbrv[RTSMB_NB_NAME_SIZE+1];	// null ended name
char ns_netName[RTSMB_NB_NAME_SIZE+1];		// space appended name
char ns_netNameAbrv[RTSMB_NB_NAME_SIZE+1];	// null ended name
char ns_globalName[RTSMB_NB_NAME_SIZE+1];	// space appended name
char ns_globalNameAbrv[RTSMB_NB_NAME_SIZE+1];	// null ended name

RTSMB_STATIC BBOOL doAnnouncements;

//============================================================================
//    IMPLEMENTATION PRIVATE FUNCTION PROTOTYPES
//============================================================================

RTSMB_STATIC word rtsmb_srv_nbns_get_next_transfer_id(void);
RTSMB_STATIC void rtsmb_srv_nbns_run_name_table (void);

RTSMB_STATIC void rtsmb_srv_nbns_send_name_register_request(word tranID, PFCHAR name, BBOOL group);
RTSMB_STATIC void rtsmb_srv_nbns_send_name_query(word tranID, PFCHAR name);
RTSMB_STATIC void rtsmb_srv_nbns_send_name_overwrite(word transID, PFCHAR name, BBOOL group);

void rtsmb_srv_browse_cycle (void){}
void rtsmb_srv_browse_finish_server_enum (PSMB_SESSIONCTX pCtx){}
long rtsmb_srv_browse_get_next_wake_timeout (void) {return -1;}
int rtsmb_srv_browse_get_role(void) {return RTSMB_SRV_BROWSE_ROLE_MASTER_BROWSER;}
dword rtsmb_srv_browse_get_server_type (void){  return SV_TYPE_SERVER | SV_TYPE_PRINTQ_SERVER | SV_TYPE_POTENTIAL_BROWSER;}
void rtsmb_srv_browse_process_message (int command, PFVOID origin, PFVOID buf, rtsmb_size size, PRTSMB_HEADER pheader) { }
void rtsmb_srv_browse_shutdown(void){}
void rtsmb_srv_nbns_cycle (void) {}
long rtsmb_srv_nbns_get_next_wake_timeout(void) {return -1;}

BBOOL rtsmb_srv_nbns_process_packet (PFBYTE buf, rtsmb_size size){ return FALSE; }
void rtsmb_srv_nbns_restart (void){}
void rtsmb_srv_nbns_shutdown(void){}
void rtsmb_srv_nbss_send_session_response (RTP_SOCKET sock, BBOOL positive) {}

BBOOL rtsmb_srv_nbns_is_in_name_table (PFCHAR name, BBOOL lookAtSuffix) { return FALSE; }



//============================================================================
//    IMPLEMENTATION PRIVATE FUNCTIONS
//============================================================================
RTSMB_STATIC word rtsmb_srv_nbns_get_next_transfer_id(void)
{
	static word lastTransID = 0;

	++lastTransID;

	return lastTransID;
}

/*
===============
 rtsmb_srv_nbns_add_name - adds a new name to the name table so that it may be claimed
 	newName - must be a valid netBios name of 16 characters
===============
*/
BBOOL rtsmb_srv_nbns_add_name (PFCHAR newName, BBOOL group, char suf, BBOOL announce)
{
	int i;
	for(i=0; i < NAME_TABLE_SIZE; i++)
	{
		if(nameTable[i].status == NS_NONAME)
		{
			rtsmb_util_make_netbios_name (nameTable[i].name, newName, (byte)suf);
			nameTable[i].group = group;
			nameTable[i].transID = rtsmb_srv_nbns_get_next_transfer_id();
			nameTable[i].announce = announce;
			nameTable[i].status = announce ? NS_PENDING : NS_REGISTERED;
			nameTable[i].nextSendBase = rtp_get_system_msec () - RTSMB_NB_BCAST_RETRY_TIMEOUT;
			nameTable[i].numSent = 0;

			if (announce)
			{
				doAnnouncements = TRUE;
			}

			return(TRUE);
		}
	}

	 RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_srv_nbns_add_name:  Name table is full\n");
	return(FALSE);
}

//============================================================================
//    INTERFACE FUNCTIONS
//============================================================================



PFCHAR rtsmb_srv_nbns_get_our_group (void)
{
	return ns_groupNameAbrv;
}

PFCHAR rtsmb_srv_nbns_get_our_name (void)
{
	return ns_netNameAbrv;
}


#if (1)
void rtsmb_nbds_cycle(long timeout) {};
void rtsmb_nbds_shutdown(void) {};
RTP_SOCKET rtsmb_nbds_get_socket (void) {return 0;};

/**
 * returns size of header
 */
int rtsmb_nbss_fill_header (PFVOID buf, rtsmb_size size, PRTSMB_NBSS_HEADER pStruct)
{
    PACK_BYTE (buf, &size, pStruct->type, -1);
//    PACK_BYTE (buf, &size, (byte) ((size > 0xFFFF) ? 0x1 : 0), -1);
    PACK_BYTE (buf, &size, (byte) (pStruct->size>>16 & 0xFF), -1);
    PACK_BYTE (buf, &size, (byte) (pStruct->size>>8 & 0xFF), -1);
    PACK_BYTE (buf, &size, (byte) (pStruct->size & 0xFF), -1);
//    PACK_WORD (buf, &size, (word) (pStruct->size & 0xFFFF), TRUE, -1);

    return RTSMB_NBSS_HEADER_SIZE;
}
#endif

#if (1)
RTSMB_STATIC BBOOL         rtsmb_nbds_initialized_ever = 0;
void rtsmb_nbds_init (void)
{
    if (rtsmb_nbds_initialized_ever == 0)
    {
        rtsmb_browse_config ();
    }
    rtsmb_nbds_initialized_ever = 1;
}
#endif

void rtsmb_srv_browse_init (void)
{
    rtsmb_nbds_init ();
}

/*
================
 void rtsmb_srv_nbns_init() -
================
*/
void rtsmb_srv_nbns_init (PFCHAR net_name, PFCHAR group_name)
{
	int i;

	lastCacheIndex = -1;
	lastQueryIndex = -1;

	rtp_sig_mutex_alloc((RTP_MUTEX *) &nameQueryTableSem, (const char*)0);

	for(i = 0; i < NAME_CACHE_SIZE; i++)
		nameCache[i].inUse = FALSE;

	for(i = 0; i < NAME_QUERY_SIZE; i++)
		nameQueryTable[i].inUse = FALSE;

	for(i = 0; i < NAME_TABLE_SIZE; i++)
		nameTable[i].status = NS_NONAME;

	if (net_name)
	{
		rtsmb_util_make_netbios_name (ns_netName, net_name, '\0');
		tc_strcpy(ns_netNameAbrv, net_name);
	}
	else
	{
		rtsmb_util_make_netbios_name (ns_netName, CFG_RTSMB_DEFAULT_NET_NAME, '\0');
		tc_strcpy(ns_netNameAbrv, CFG_RTSMB_DEFAULT_NET_NAME);
	}
	rtsmb_util_latin_string_toupper (ns_netNameAbrv);

	if (group_name)
	{
		rtsmb_util_make_netbios_name (ns_groupName, group_name, '\0');
		tc_strcpy(ns_groupNameAbrv, group_name);
	}
	else
	{
		rtsmb_util_make_netbios_name (ns_groupName, CFG_RTSMB_DEFAULT_GROUP_NAME, '\0');
		tc_strcpy(ns_groupNameAbrv, CFG_RTSMB_DEFAULT_GROUP_NAME);
	}
	rtsmb_util_latin_string_toupper (ns_groupNameAbrv);

	rtsmb_util_make_netbios_name (ns_globalName, RTSMB_NB_DEFAULT_NAME, '\0');
	tc_strcpy(ns_globalNameAbrv, RTSMB_NB_DEFAULT_NAME);
	rtsmb_util_latin_string_toupper (ns_globalNameAbrv);

	rtsmb_srv_nbns_add_name(ns_netName, FALSE, RTSMB_NB_NAME_TYPE_WORKSTATION, TRUE);
	rtsmb_srv_nbns_add_name(ns_netName, FALSE, RTSMB_NB_NAME_TYPE_SERVER, TRUE);//file service

	rtsmb_srv_nbns_add_name(ns_globalName, FALSE, RTSMB_NB_NAME_TYPE_SERVER, FALSE);

	rtsmb_srv_nbns_add_name(ns_groupName, TRUE, RTSMB_NB_NAME_TYPE_WORKSTATION, TRUE);
	//rtsmb_srv_nbns_add_name(ns_groupName, TRUE, RTSMB_NB_NAME_TYPE_ELECTION_SERVICE, TRUE);
	rtsmb_srv_nbns_add_name(ns_groupName, TRUE, RTSMB_NB_NAME_TYPE_SERVER, TRUE);
}

#include "smbread.h"

/**
 * returns size of header
 */
int rtsmb_nbss_read_header (PFVOID buf, rtsmb_size size, PRTSMB_NBSS_HEADER pStruct)
{
    byte header_bytes[4];
//    byte command, flags;
//    word datasize;
//    READ_BYTE (buf, &size, &command, -1);
//    READ_BYTE (buf, &size, &flags, -1);
//    READ_WORD (buf, &size, &datasize, TRUE, -1);
//    pStruct->type = command;
//    pStruct->size = (dword) (datasize + (word)((flags & 0x1) ? 0xFFFF : 0));
    READ_BYTE (buf, &size, &header_bytes[0], -1);
    READ_BYTE (buf, &size, &header_bytes[1], -1);
    READ_BYTE (buf, &size, &header_bytes[2], -1);
    READ_BYTE (buf, &size, &header_bytes[3], -1);

    pStruct->type = header_bytes[0];
    pStruct->size = ((dword)header_bytes[1]<<16) +  ((dword)header_bytes[2]<<8) +((dword)header_bytes[3]);

    return RTSMB_NBSS_HEADER_SIZE;
}

/**
 * At this point in the packet's life, only the first few bytes will be
 * read, in order to get the NetBios header.  This gives us the length
 * of the message, which we will then pull from the socket.
 *
 * Returns FALSE if we should end the session.
 */

BBOOL rtsmb_srv_nbss_process_packet (PSMB_SESSIONCTX pSCtx)    // Called from rtsmb_srv_net_session_cycle
{
	RTSMB_NBSS_HEADER header;
    byte header_bytes[4];
RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_srv_nbss_process_packet: call rtsmb_net_read.\n");
	if (rtsmb_net_read (pSCtx->sock, pSCtx->readBuffer, pSCtx->readBufferSize, RTSMB_NBSS_HEADER_SIZE) == -1)
	{
		return FALSE;
	}
	if (rtsmb_nbss_read_header (pSCtx->readBuffer, RTSMB_NBSS_HEADER_SIZE, &header) < 0)
	{
		return FALSE;
	}
	switch (header.type)
	{
		case RTSMB_NBSS_COM_MESSAGE:	/* Session Message */
            if (!header.size)
            {
               RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"Warning: rtsmb_srv_nbss_process_packet ignoring 0-length packet\n");
            }
            else
            {
RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_srv_nbss_process_packet : call SMBS_ProcSMBPacket(%d).\n",header.size);
			  if (!SMBS_ProcSMBPacket (pSCtx, header.size))   //rtsmb_srv_nbss_process_packet stubs ?
			  {
			    return FALSE;
			  }
			}
			break;

		case RTSMB_NBSS_COM_REQUEST:	/* Session Request */

//			if (!rtsmb_srv_nbss_process_request (pSCtx->sock, &header))
//			{
//				return FALSE;
//			}
			break;

		default:
          RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_srv_nbss_process_packet: Unhandled packet type %X\n", header.type);
		break;
	}

	return TRUE;
}


#endif /* INCLUDE_RTSMB_SERVER */
