/*                                                                         */
/* EBSnet - RTSMB                                                          */
/*                                                                         */
/* Copyright EBSnet Inc. , 2003                                            */
/* All rights reserved.                                                    */
/* This code may not be redistributed in source or linkable object form    */
/* without the consent of its author.                                      */
/*                                                                         */
/* Module description:                                                     */
/* Handles authentication, including groups, users, passwords              */
/*                                                                         */

#include "smbdefs.h"
#include "rtpwcs.h"
#include "rtpprint.h"
#include "smbdebug.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvauth.h"
#include "srvshare.h"
#include "srvutil.h"
#include "srvrsrcs.h"

#include "srvcfg.h"
#include "smbutil.h"

#define DISPLAY_USERS 0

RTSMB_STATIC short getUserIdFromName (PFRTCHAR name);

#if (DISPLAY_USERS)
void smbs_display_users(void)
{
int i, j;
char rtsmb_user[CFG_RTSMB_MAX_USERNAME_SIZE + 1];  /* ascii user name */
int uid;

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "************** USERS ****************\n"); //    #if (DISPLAY_USERS)
    for (i = 0; i < prtsmb_srv_ctx->max_users; i++)
    {
        if (prtsmb_srv_ctx->userList.users[i].inUse)
        {
            rtsmb_util_rtsmb_to_ascii(prtsmb_srv_ctx->userList.users[i].name,
                                      rtsmb_user, CFG_RTSMB_USER_CODEPAGE);

            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "USER TABLE ENTRY: %d USER: %s; PASSWORD: %s\n", i,rtsmb_user,prtsmb_srv_ctx->userList.users[i].password);

            uid = getUserIdFromName (prtsmb_srv_ctx->userList.users[i].name);
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"USER TABLE ENTRY: UID %d\n", uid);

            for (j = 0; j < prtsmb_srv_ctx->groupList.numGroups; j++)
            {
                if (prtsmb_srv_ctx->userList.users[uid].groups[j])
                {
                    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"USER TABLE ENTRY: in GROUP %d\n", j); //    #if (DISPLAY_USERS)
                }
            }
        }
    }
}
#endif

/**
 *
 * These functions are used to authenticate users
 * for access to shares.
 */

RTSMB_STATIC
short getGroupIdFromName (PFRTCHAR name)
{
    byte i;

    for (i = 0; i < prtsmb_srv_ctx->groupList.numGroups; i++)
    {
        if (rtsmb_casencmp (name, prtsmb_srv_ctx->groupList.groups[i].name, CFG_RTSMB_MAX_GROUPNAME_SIZE, CFG_RTSMB_USER_CODEPAGE) == 0)
        {
            return i;
        }
    }

    return -1;
}

RTSMB_STATIC
short getUserIdFromName (PFRTCHAR name)
{
    byte i;

    for (i = 0; i < prtsmb_srv_ctx->max_users; i++)
    {
        if (prtsmb_srv_ctx->userList.users[i].inUse &&
            !rtsmb_casencmp (name, prtsmb_srv_ctx->userList.users[i].name, CFG_RTSMB_MAX_USERNAME_SIZE, CFG_RTSMB_USER_CODEPAGE))
        {
            return i;
        }
    }

    return -1;
}

static PUSERDATA getuserSructureFromName(PFRTCHAR name,short *uid)
{
PUSERDATA user=0;
    *uid = getUserIdFromName (name);
    if (*uid >= 0)
    {
        user = &prtsmb_srv_ctx->userList.users[*uid];
    }
    return user;
}

word Auth_AuthenticateUser_lm (PSMB_SESSIONCTX pCtx, PFBYTE lm_response, PFRTCHAR name, word *authId)
{
    short uid;
    BYTE output24[24];
    word rv = AUTH_NOACCESS;
    PUSERDATA user;

    CLAIM_AUTH ();
    user = getuserSructureFromName(name, &uid);
    if (user)
    {
        cli_util_encrypt_password_pre_nt (user->password, pCtx->encryptionKey, output24);
        if (tc_memcmp(lm_response, output24, 24) == 0)
        {
          (*authId) = (word)uid;
           rv = 0;
        }
    }
    RELEASE_AUTH ();
    return rv;
}

word Auth_AuthenticateUser_ntlm (PSMB_SESSIONCTX pCtx, PFBYTE lm_response, PFRTCHAR name, word *authId)
{
    short uid;
    BYTE output24[24];
    word rv = AUTH_NOACCESS;
    PUSERDATA user;

    CLAIM_AUTH ();
    user = getuserSructureFromName(name, &uid);
    if (user)
    {
        cli_util_encrypt_password_ntlm (user->password, pCtx->encryptionKey, output24);
        if (tc_memcmp(lm_response, output24, 24) == 0)
        {
          (*authId) = (word)uid;
           rv = 0;
        }
    }
    RELEASE_AUTH ();
    return rv;
}

// if NT_LM security ansi_password is actually the LM security code
// domainname and uni_password only matter for lmv2
word Auth_AuthenticateUser_ntlm2 (PSMB_SESSIONCTX pCtx,PFBYTE clientNonce, PFBYTE ntlm2_response, PFRTCHAR name, word *authId)
{
    short uid;
    BYTE output24[24];
    word rv = AUTH_NOACCESS;
    PUSERDATA user;

    CLAIM_AUTH ();
    user = getuserSructureFromName(name, &uid);
    if (user)
    {
        cli_util_encrypt_password_ntlm2 (clientNonce,pCtx->encryptionKey, user->password, output24);
        if (tc_memcmp(ntlm2_response, output24, 24) == 0)
        {
          (*authId) = (word)uid;
           rv = 0;
        }
    }
    RELEASE_AUTH ();
    return rv;
}


// The NTLMv2 User Session Key
//
// Used when the NTLMv2 response is sent. Calculation of this key is very similar to the LMv2 User Session Key:
//
// The NTLMv2 hash is obtained (as calculated previously).
// The NTLMv2 "blob" is obtained (as used in the NTLMv2 response).
// The challenge from the Type 2 message is concatenated with the blob. The HMAC-MD5 message authentication code algorithm is applied to this value using the NTLMv2 hash as the key, resulting in a 16-byte output value.
// The HMAC-MD5 algorithm is applied to this value, again using the NTLMv2 hash as the key. The resulting 16-byte value is the NTLMv2 User Session Key.
//
// ntlmnv2 handler - not done yet See http://davenport.sourceforge.net/ntlm.html#theNtlmResponse
word Auth_AuthenticateUser_ntlmv2 (PSMB_SESSIONCTX pCtx, PFBYTE ntlm_response_blob, size_t ntlm_response_blob_length, PFRTCHAR name, PFRTCHAR domainname, word *authId)
{
    word rv = AUTH_NOACCESS;
    short uid;
    BYTE output[1024];

    PUSERDATA user;

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Auth_AuthenticateUser_ntlmv2 is a stack hog\n");
    CLAIM_AUTH ();
    user = getuserSructureFromName(name, &uid);
    if (user)
    {
        cli_util_encrypt_password_ntlmv2 (user->password, pCtx->encryptionKey, ntlm_response_blob, ntlm_response_blob_length, name, domainname,output);
        if (tc_memcmp(ntlm_response_blob, output, 16) == 0)
        {
          (*authId) = (word)uid;
           rv = 0;
        }
    }
    RELEASE_AUTH ();
    return rv;
}


word Auth_AuthenticateUser_lmv2 (PSMB_SESSIONCTX pCtx, PFBYTE clientNonce, PFBYTE lm_response, PFRTCHAR name, PFRTCHAR domainname, word *authId)
{
    word rv = AUTH_NOACCESS;
    short uid;
    BYTE output24[24];
    PUSERDATA user;


    CLAIM_AUTH ();
    user = getuserSructureFromName(name, &uid);
    if (user)
    {
        cli_util_encrypt_password_lmv2 (user->password, pCtx->encryptionKey, clientNonce, name, domainname,output24);
        if (tc_memcmp(lm_response, output24, 24) == 0)
        {
          (*authId) = (word)uid;
           rv = 0;
        }
    }
    RELEASE_AUTH ();
    return rv;
}

// =================================================================================
// Auth_AuthenticateUser and DoPasswordsMatch() are really ugly, should be able to remove but not just yet
// =================================================================================
//
//
//
word Auth_AuthenticateUser (PSMB_SESSIONCTX pCtx, PFRTCHAR name, PFRTCHAR domainname, PFCHAR ansi_password, PFCHAR uni_password, word *authId)
{
    short uid;
    PUSERDATA user;
    word rv = AUTH_NOACCESS;

    CLAIM_AUTH ();
    uid = getUserIdFromName (name);
    if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL ,"\nUser \" %ls ", name);}
    if (domainname)
    {
       if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL," \" with domainname \" %ls", domainname);}
    }
     if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL," \" is trying to access the share created on this server\n");}

    if (uid >= 0)
    {
        user = &prtsmb_srv_ctx->userList.users[uid];

        if (Auth_DoPasswordsMatch (pCtx, name, domainname, user->password,
                                (PFBYTE) ansi_password, (PFBYTE) uni_password))
        {
            (*authId) = (word)uid;
            rv = 0;
        }
    }

    /* Commenting below code to allow guest login with only username "guest" and password "guest" */
    /*if (rv == AUTH_NOACCESS && prtsmb_srv_ctx->guestAccount != -1)
    {
        (*authId) = prtsmb_srv_ctx->guestAccount;
        rv = AUTH_GUEST;
    }*/

    RELEASE_AUTH ();

    if (rv == 0)
    {
         if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL,"Auth_AuthenticateUser:  User \" %ls \" granted access.\n", name);}
    }
    else if (rv == AUTH_GUEST)
    {
         if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL,"Auth_AuthenticateUser:  User \" %ls  \" granted guest access.\n");}
    }
    else
    {
         if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL,"Auth_AuthenticateUser:  User \" %ls  \" not granted access.\n", name);}
    }

    return rv;
}

BBOOL isInGroup (word authId, word groupId)
{
    return prtsmb_srv_ctx->userList.users[authId].groups[groupId];
}


void setMode (PACCESS_TABLE table, word tid, byte mode)
{
    byte byteNum;
    byte bitNum;    /* first of two bits */
    byte *actualByte;

    byteNum = (byte)(tid / 4);
    bitNum =  (byte)((tid % 4)*2);  /* first of two bits */
    actualByte = &table->table [byteNum];

    (*actualByte) |= (byte)(0xc0 >> bitNum);
    (*actualByte) ^= (byte)(0xc0 >> bitNum);
    (*actualByte) |= (byte) (mode << (6 - bitNum));
}

byte getMode (PACCESS_TABLE table, word tid)
{
    byte byteNum;
    byte bitNum;
    byte actualByte;

    byteNum = (byte) (tid / 4);
    bitNum = (byte) ((tid % 4) * 2);  /* first of two bits */
    actualByte = table->table [byteNum];

    return
        (byte)((actualByte & (byte)(0xc0 >> bitNum))>>(6 - (int)bitNum));
}

byte mergeAccessRights (byte one, byte two)
{
    if (one == two)
    {
         return one;
    }
    else if (one == SECURITY_READWRITE)
    {
         return one;
    }
    else if (two == SECURITY_READWRITE)
    {
         return two;
    }
    else if (one == SECURITY_NONE)
    {
         return two;
    }
    else if (two == SECURITY_NONE)
    {
         return one;
    }
    else
    {
         return SECURITY_READWRITE;
    }
}


// if NT_LM security plaintext is the password from the user structure
// if NT_LM security ansi_password is actually the LM security code
// domainname and uni_password only matter for lmv2

// Auth_AuthenticateUser and DoPasswordsMatch() are really ugly, should be able to remove but not just yet

BBOOL Auth_DoPasswordsMatch (PSMB_SESSIONCTX pCtx, PFRTCHAR name, PFRTCHAR domainname,
                             PFCHAR  plaintext, PFBYTE ansi_password, PFBYTE uni_password) /*_YI_ */
{
    BBOOL ret_val;
#if (INCLUDE_RTSMB_ENCRYPTION)
    byte passbuf [24];
#endif

    if(plaintext) /* if there is no need to check passwords, don't */
    {
        ret_val = FALSE;
#if (INCLUDE_RTSMB_ENCRYPTION)
        if (pCtx->dialect >= NT_LM)
        {
        int i;
            rtsmb_dump_bytes("Auth_DoPasswordsMatch: ansi_password :", ansi_password, 24, DUMPBIN);
        }

        if (pCtx->dialect >= NT_LM &&
            tc_memcmp (cli_util_encrypt_password_ntlm (plaintext, pCtx->encryptionKey, passbuf), ansi_password, 24)==0)
        {
            ret_val = TRUE;
        }
        else if (tc_memcmp (cli_util_encrypt_password_pre_nt (plaintext, pCtx->encryptionKey, passbuf), ansi_password, 24)==0)
        {
            ret_val = TRUE;
        }
        else if (name && domainname && uni_password &&
                 (tc_memcmp(cli_util_encrypt_password_lmv2 (plaintext, pCtx->encryptionKey, (PFCHAR)passbuf, (PFRTCHAR)&uni_password[32], name, (PFCHAR) domainname), ansi_password, 24)==0))
        {
            ret_val = TRUE;
        }
#else
        if (tc_strcmp (plaintext, ansi_password) == 0)
        {
            ret_val = TRUE;
        }
#endif
    }
    else
        ret_val = TRUE;
    return (ret_val);
}

/* returns the accumulated access rights due to group membership     */
byte Auth_BestAccess (PSMB_SESSIONCTX pCtx, word tid)
{
    word i;
    PUSER user;
    byte best = SECURITY_NONE;

    user = SMBU_GetUser (pCtx, pCtx->uid);

    CLAIM_AUTH ();
    for (i = 0; i < prtsmb_srv_ctx->groupList.numGroups; i ++)
    {
        if (isInGroup (user->authId, i) == TRUE)
        {
            byte actualMode = getMode (&prtsmb_srv_ctx->groupList.groups[i], tid);

            best = mergeAccessRights (best, actualMode);

/*          PRINTF (("user %s in group " RTSMB_STR_TOK " gets permissions %i\n",                                     */
/*              prtsmb_srv_ctx->userList.users[user->authId].name, prtsmb_srv_ctx->groupList.groups[i].name, best));    */

            /* early exit, since can't get better than this */
            if (best == SECURITY_READWRITE)
                break;
        }
    }
    RELEASE_AUTH ();

    return best;
}

/* assume valid tid */
BBOOL Auth_HasAccess (PSMB_SESSIONCTX pCtx, word tid, byte mode) /* mode is either 0, 1, or 2 (read, write, or both) */
{
    word access;

    if (mode == SECURITY_NONE)
    {
        return TRUE; /* if for some reason, they ask for no access */
    }
    access = Auth_BestAccess (pCtx, tid);

    return  (access != SECURITY_NONE &&
            (access == SECURITY_READWRITE ||
             mode == access));
}

BBOOL Auth_RegisterGroup (PFRTCHAR name)
{
    byte b = 0;
    int i;
    BBOOL rv = TRUE;

    CLAIM_AUTH ();
    if (prtsmb_srv_ctx->groupList.numGroups == prtsmb_srv_ctx->max_groups)
    {
        rv = FALSE;
    }
    else
    {
        for (i = 0; i < 8; i += 2)
        {
            b = b | (byte)(SECURITY_NONE << i);
        }

        rtsmb_ncpy (prtsmb_srv_ctx->groupList.groups[prtsmb_srv_ctx->groupList.numGroups].name, name, CFG_RTSMB_MAX_GROUPNAME_SIZE);
        tc_memset (prtsmb_srv_ctx->groupList.groups[prtsmb_srv_ctx->groupList.numGroups].table, b, sizeof (prtsmb_srv_ctx->groupList.groups[prtsmb_srv_ctx->groupList.numGroups].table));

        prtsmb_srv_ctx->groupList.numGroups++;
    }
    RELEASE_AUTH ();

    if (rv)
    {
         if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL,"Auth_RegisterGroup:  Successfully registered group \" %ls \n",name);}
    }
    else
    {
         if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL,"Auth_RegisterGroup:  Failed registered group \" %ls \n",name);}
    }

    return rv;
}

BBOOL Auth_AssignGroupPermission (PFRTCHAR group, PFRTCHAR share, byte mode)
{
    short gid;
    int tid;
    BBOOL rv = TRUE;

    CLAIM_AUTH ();
    if ((gid = getGroupIdFromName (group)) < 0)
        rv = FALSE;

    if ((tid = SR_GetTreeIdFromName (share)) < 0)
        rv = FALSE;

    if (rv)
        setMode (&prtsmb_srv_ctx->groupList.groups[gid], (word)tid, mode);
    RELEASE_AUTH ();

    if (rv)
    {
         if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL,"Auth_AssignGroupPermission:  Successfully assigned group \" %ls  \" permissions %d  for share \" %ls \n", group,mode,share);}
    }
    else
    {
         if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"Auth_AssignGroupPermission:  Failed to assigned group \" %ls  \" permissions %d  for share \" %ls \n", group,mode,share);}
    }

    return rv;
}

BBOOL Auth_RegisterUser (PFRTCHAR name, PFCHAR password)
{
    byte i;
    PUSERDATA user;
    BBOOL rv = TRUE;

    CLAIM_AUTH ();
    for (i = 0; i < prtsmb_srv_ctx->max_users; i++)
    {
        if (prtsmb_srv_ctx->userList.users[i].inUse == FALSE)
        {
            user = &prtsmb_srv_ctx->userList.users[i];
            break;
        }
    }

    if (i == prtsmb_srv_ctx->max_users)
    {
         if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"Auth_RegisterUser exceeded max_users\n");}
        rv = FALSE;
    }

    if (rv)
    {
        rtsmb_char rtsmb_guest [CFG_RTSMB_MAX_USERNAME_SIZE + 1];

        rtsmb_util_ascii_to_rtsmb (SMB_GUESTNAME, rtsmb_guest, CFG_RTSMB_USER_CODEPAGE);

        if (!rtsmb_casecmp (name, rtsmb_guest, CFG_RTSMB_USER_CODEPAGE))
        {
            prtsmb_srv_ctx->guestAccount = i;
        }

        user->inUse = TRUE;
        rtsmb_ncpy (user->name, name, CFG_RTSMB_MAX_USERNAME_SIZE);

        if (password)
        {
            user->password = user->password_buf;
            tc_memset (user->password, '\0', sizeof (user->password));  /* we want to pad it with nulls for encryption */
            tc_strncpy (user->password, password, CFG_RTSMB_MAX_PASSWORD_SIZE);
        }
        else
        {
            user->password = (PFCHAR)0;
        }

        tc_memset (user->groups, FALSE, prtsmb_srv_ctx->max_groups);
    }
    RELEASE_AUTH ();

    if (rv)
    {
        if (name)
        {
             if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL,"Auth_RegisterUser:  success registering user \" %ls  \" with password %s \n", name, password?password:"NO PASSWORD");}
        }
    }
    else
    {
        if (name)
        {
             if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"Auth_RegisterUser:  Failed to register user \" %ls  \" with password %s \n", name, password?password:"NO PASSWORD");}
        }
    }
#if (DISPLAY_USERS)
    if (rv == RTP_TRUE)
    {
        smbs_display_users();
    }
#endif
    return rv;
}

// Return >0 if it found a password and copied it to the buffer
int Auth_GetPasswordFromUserName(PFRTCHAR name,PFRTCHAR pwresult)
{
int   rv=0;
short uid;
PUSERDATA user;

  CLAIM_AUTH ();
  user = getuserSructureFromName(name, &uid);
  if (user)
  {
    // Convert the stored password to unicode and return it
     rtsmb_util_ascii_to_unicode (user->password ,pwresult, CFG_RTSMB_USER_CODEPAGE);
     rv = rtsmb_len(pwresult);
  }
  RELEASE_AUTH ();
  return rv;
}

BBOOL Auth_DeleteUser (PFRTCHAR name)
{
    short uid;
    BBOOL rv = TRUE;
    rtsmb_char rtsmb_guest [CFG_RTSMB_MAX_USERNAME_SIZE + 1];

    rtsmb_util_ascii_to_rtsmb (SMB_GUESTNAME, rtsmb_guest, CFG_RTSMB_USER_CODEPAGE);

    CLAIM_AUTH ();
    uid = getUserIdFromName (name);

    if (uid < 0)
        rv = FALSE;
    else
        prtsmb_srv_ctx->userList.users[uid].inUse = FALSE;

    if (rv && !rtsmb_casecmp (name, rtsmb_guest, CFG_RTSMB_USER_CODEPAGE))
        prtsmb_srv_ctx->guestAccount = -1;
    RELEASE_AUTH ();

    if (rv)
    {
         if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL,"Auth_DeleteUser:  Successfully deleted user \" %ls  \".\n", name);}
    }
    else
    {
         if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"Auth_DeleteUser:  Failed to delete user \" %ls  \".\n", name);}
    }

    return rv;
}

BBOOL Auth_AddUserToGroup (PFRTCHAR user, PFRTCHAR group)
{
    short uid;
    short gid;
    BBOOL rv = TRUE;

    CLAIM_AUTH ();
    uid = getUserIdFromName (user);
    gid = getGroupIdFromName (group);

    if (uid < 0 || gid < 0)
        rv = FALSE;
    else
        prtsmb_srv_ctx->userList.users[uid].groups[gid] = TRUE;
    RELEASE_AUTH ();

    if (rv)
    {
         if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL,"Auth_AddUserToGroup:  Successfully add user \" %ls  \" to group \" %ls \n", user, group);}
    }
    else
    {
         if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"Auth_AddUserToGroup:  Failed to add user \" %ls  \" to group \" %ls \n", user, group);}
    }

    return rv;
}

BBOOL Auth_RemoveUserFromGroup (PFRTCHAR user, PFRTCHAR group)
{
    short uid;
    short gid;
    BBOOL rv = TRUE;

    CLAIM_AUTH ();
    uid = getUserIdFromName (user);
    gid = getGroupIdFromName (group);

    if (uid < 0 || gid < 0)
        rv = FALSE;
    else
        prtsmb_srv_ctx->userList.users[uid].groups[gid] = FALSE;
    RELEASE_AUTH ();

    if (rv)
    {
         if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL,"Auth_RemoveUserFromGroup:  Successfully remove user \" %ls  \" from group \" %ls \n", user, group);}
    }
    else
    {
         if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"Auth_RemoveUserFromGroup:  Failed to remove user \" %ls  \" to group \" %ls \n", user, group);}
    }

    return rv;
}

void Auth_SetMode (byte mode)
{
    if (mode == AUTH_USER_MODE || mode == AUTH_SHARE_MODE)
    {
        CLAIM_AUTH ();
        prtsmb_srv_ctx->shareMode = mode;
        RELEASE_AUTH ();
    }

    if (mode == AUTH_USER_MODE)
    {
         if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL,"Auth_SetMode:  Set server mode to user mode.\n");}
    }
    else if (mode == AUTH_SHARE_MODE)
    {
         if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"Auth_SetMode:  Set server mode to share mode.\n");}
    }
    else
    {
         if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"Auth_SetMode:  Ignoring unrecognized mode.\n");}
    }
}

byte Auth_GetMode (void)
{
    byte temp;

    CLAIM_AUTH ();
    temp = prtsmb_srv_ctx->shareMode;
    RELEASE_AUTH ();

    return temp;
}

void Auth_Init (void)
{
    CLAIM_AUTH ();
    prtsmb_srv_ctx->shareMode = AUTH_SHARE_MODE;
    prtsmb_srv_ctx->guestAccount = -1;
    RELEASE_AUTH ();

     if (prtsmb_srv_ctx->display_login_info)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL,"Auth_Init:  Initializing authorization data.\n");}
}

#endif /* INCLUDE_RTSMB_SERVER */
