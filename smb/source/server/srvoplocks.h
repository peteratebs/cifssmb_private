#ifndef __SRVOPLOCKS__
#define __SRVOPLOCKS__

#include <stdint.h>

#define CFG_RTSMB_MAX_OPLOCKS  1024

typedef uint64_t unique_userid_t;


// Return types: Enums don't work in C anyway
#define oplock_c_create_return_e int
#define oplock_c_create_continue 0
#define oplock_c_create_yield    1

#define oplock_c_break_acknowledge_return_e int
#define oplock_c_break_acknowledge_error     0
#define oplock_c_break_acknowledge_continue  1

#define OplockStateNone      0
#define OplockStateHeld      1
#define OplockStateBreaking  2


#define SMB2_OPLOCK_LEVEL_NONE              0x00 //No oplock is requested.
#define SMB2_OPLOCK_LEVEL_II                0x01 // A level II oplock is requested.
#define SMB2_OPLOCK_LEVEL_EXCLUSIVE         0x08 // An exclusive oplock is requested.
#define SMB2_OPLOCK_LEVEL_BATCH             0x09   // A batch oplock is requested.
#define SMB2_OPLOCK_LEVEL_LEASE             0xFF   // A lease is requested. If set, the request packet MUST contain an SMB2_CREATE_REQUEST_LEASE (section 2.2.13.2.8) create context. This value is not valid for the SMB 2.0.2 dialect.

#define SMB2WAITOPLOCKFLAGREPLY  0x02
#define SMB2WAITLOCKFLAGREGION   0x08   /* not used yet */

#define OPLOCK_DEFAULT_DURATION  4000                 // for testing

#ifdef __cplusplus
extern "C" {
#endif

oplock_c_create_return_e oplock_c_check_create_path(struct net_sessionctxt *current_session, uint8_t *unique_fileid, unique_userid_t unique_userid, uint8_t requested_lock_level);
void oplock_c_create(struct net_sessionctxt *current_session, PFID pfid,unique_userid_t unique_userid, uint8_t requested_lock_level);
void oplock_c_break_clear_pending_break_send_queue(void);
void oplock_c_break_send_pending_breaks(void);
oplock_c_break_acknowledge_return_e oplock_c_break_acknowledge(PNET_SESSIONCTX pnCtx, uint8_t *unique_fileid, unique_userid_t unique_userid, uint8_t granted_lock_level,uint32_t *pstatus);
void oplock_c_break_check_waiting_break_requests(void);
void oplock_c_close(PNET_SESSIONCTX pnCtx, PFID pFid);
// in smboplocks2
void SendOplockBreak(RTP_SOCKET sock, byte *unique_fileid,uint8_t requested_oplock_level);
#ifdef __cplusplus
}
#endif

#endif //  __SRVOPLOCKS__
