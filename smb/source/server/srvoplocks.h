#ifndef __SRVOPLOCKS__
#define __SRVOPLOCKS__

#include <stdint.h>

#define CFG_RTSMB_MAX_OPLOCKS  1024

typedef uint64_t unique_userid_t;
typedef void * opploc_Cptr;

#define ITERATEOPLOCKHEAP for(int i=0; i < CFG_RTSMB_MAX_OPLOCKS; i++)

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

#define SMB2SENDOPLOCKFLAGBREAK  0x02
#define SMB2WAITOPLOCKFLAGREPLY  0x04
#define SMB2OPLOCKFLAGHELD       0x08
#define SMB2WAITLOCKFLAGREGION   0x10   /* not used yet */


#ifdef __cplusplus
extern "C" {
#endif

opploc_Cptr oplock_c_find_oplock(uint8_t *unique_fileid);
opploc_Cptr oplock_c_new_fid_oplock(PFID pfid, unique_userid_t unique_userid_of_owner,uint8_t held_lock_level);

oplock_c_create_return_e oplock_c_check_create_path(uint8_t *unique_fileid, unique_userid_t unique_userid, uint8_t requested_lock_level);
void oplock_c_create(PFID pfid,uint8_t requested_lock_level);
void oplock_c_close(PFID pfid);
void oplock_c_delete(PFID pfid);
void oplock_c_new_unlocked_fid(PFID pfid);

oplock_c_break_acknowledge_return_e oplock_c_break_acknowledge(uint8_t *unique_fileid, unique_userid_t unique_userid, uint8_t requested_lock_level,uint32_t *pstatus);

void oplock_c_break_update_pending_locks(uint8_t *unique_fileid, uint8_t oplock_level);
void oplock_c_break_send_pending_breaks(void);
void oplock_c_break_check_wating_break_requests();

// in smboplocks2
void SendOplockBreak(PFID pfid);

#ifdef __cplusplus
}
#endif

#endif //  __SRVOPLOCKS__
