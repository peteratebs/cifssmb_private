#ifndef __SRVNOTIFY__
#define __SRVNOTIFY__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// Message format sent over signal_port_number from OS to rtsmb to signal a notify event
#if (0)
typedef struct rtsmbNotifyMessage_s {
  uint16_t session_index;                          // From rtplatform_notify_request_args
  uint16_t notify_index;                           // From rtplatform_notify_request_args
  uint8_t  file_id[16];                            // From rtplatform_notify_request_args
  uint32_t payloadsize;                            // Number of bytes to follow, these will be appended to a notify alert message and send to the client
// Payload
}  __attribute__((packed)) rtsmbNotifyMessage;
#endif

// Structure used to pass notify requests to the OS
typedef struct rtplatform_notify_request_args_s {
  int      signal_port_number;                                              // UDP port number to send notify messages to on localhost
  uint64_t SessionId;                                                       // From the request packet also accessible through session index
  uint16_t session_index;                                                   // small integer value 0 to MAX_SESSIONS to include in notify message
  uint16_t notify_index;                                                    // small integer value 0 to MAX_NOTIFIES_PER_SESSION  to include in notify message
  uint64_t AsyncId;                                                         // Async ID of async pending reply to notify request
  uint64_t MessageId;                                                       // Message ID from the header so we can use it it in send completion
  uint16_t smb_protocol;                                                    // SMB protocol, 1 or 2. TBD if preformatted replies are different
  uint16_t tid;                                                             //
  uint16_t Flags;                                                           //
  uint8_t  file_id[16];                                                     // 16 bit file ID, INODE number is encoded
  uint32_t max_notify_message_size;                                         // Maximum payload size to embed in notify messages
  uint32_t completion_filter;                                               // 0 means clear or others below.
  // Note: tbd: session_index:notify_index== N:0xffff && completion_filter == 0 could be used to clear all notifies for a session
}  rtplatform_notify_request_args;


typedef struct rtplatform_notify_control_object_s {
  int    rtplatform_notify_request;     // Handle returned from the OS for the request
  size_t  next_location_offset;
  size_t  format_buffer_size;
  int     format_buffer_full;           // Set to 1 if we exceed the allowed buffer size. Copying Microsoft, if true we still respond but with no content.

  size_t  formatted_content_size;
  uint8_t *message_buffer; // Points to preformatted rtsmbNotifyMessage structure prior to format_buffer
//  rtsmbNotifyMessage *pmessage; // Typed alias for message_buffer
  uint8_t *format_buffer;  // Copy of the request
//  rtplatform_notify_request_args args;  // Copy of the request
} rtplatform_notify_control_object;


// API for the OS to queue up and send notifies
void send_notify_request_from_alert(int wd, char *name, uint32_t mapped_masked);
int find_notify_request_from_alert(int wd);



#define SMB2_WATCH_TREE  0x0001
// Completion filters values
// These have the same meaning for SMBV1 and V2

#define FILE_NOTIFY_CHANGE_FILE_NAME    0x00000001 // The client is notified if a file-name changes.
#define FILE_NOTIFY_CHANGE_DIR_NAME     0x00000002 // The client is notified if a directory name changes.
#define FILE_NOTIFY_CHANGE_ATTRIBUTES   0x00000004 // The client is notified if a file's attributes change. Possible file attribute values are specified in [MS-FSCC] section 2.6.
#define FILE_NOTIFY_CHANGE_SIZE         0x00000008 // The client is notified if a file's size changes.
#define FILE_NOTIFY_CHANGE_LAST_WRITE   0x00000010 // The client is notified if the last write time of a file changes.
#define FILE_NOTIFY_CHANGE_LAST_ACCESS  0x00000020 // The client is notified if the last access time of a file changes.
#define FILE_NOTIFY_CHANGE_CREATION     0x00000040 // The client is notified if the creation time of a file changes.
#define FILE_NOTIFY_CHANGE_EA           0x00000080 // The client is notified if a file's extended attributes (EAs) change.
#define FILE_NOTIFY_CHANGE_SECURITY     0x00000100 // The client is notified of a file's access control list (ACL) settings change.
#define FILE_NOTIFY_CHANGE_STREAM_NAME  0x00000200 // The client is notified if a named stream is added to a file.
#define FILE_NOTIFY_CHANGE_STREAM_SIZE  0x00000400 // The client is notified if the size of a named stream is changed.
#define FILE_NOTIFY_CHANGE_STREAM_WRITE 0x00000800 // The client is notified if a named stream is modified.


#define FILE_ACTION_ADDED              0x00000001       // The file was added to the directory.
#define FILE_ACTION_REMOVED            0x00000002       // The file was removed from the directory.
#define FILE_ACTION_MODIFIED           0x00000003       // The file was modified. This may be a change to the data or attributes of the file.
#define FILE_ACTION_RENAMED_OLD_NAME   0x00000004       // The file was renamed, and this is the old name. If the new name resides within the directory being monitored, the client will also receive the FILE_ACTION_RENAMED_NEW_NAME bit value as described in the next list item. If the new name resides outside of the directory being monitored, the client will not receive the FILE_ACTION_RENAMED_NEW_NAME bit value.
#define FILE_ACTION_RENAMED_NEW_NAME   0x00000005       // The file was renamed, and this is the new name. If the old name resides within the directory being monitored, the client will also receive the FILE_ACTION_RENAME_OLD_NAME bit value. If the old name resides outside of the directory being monitored, the client will not receive the FILE_ACTION_RENAME_OLD_NAME bit value.
#define FILE_ACTION_ADDED_STREAM       0x00000006       // The file was added to a named stream.
#define FILE_ACTION_REMOVED_STREAM     0x00000007       // The file was removed from the named stream.
#define FILE_ACTION_MODIFIED_STREAM    0x00000008       // The file was modified. This may be a change to the data or attributes of the file.
#define FILE_ACTION_REMOVED_BY_DELETE  0x00000009       // The file was removed by delete.




#ifdef __cplusplus
}
#endif

#endif // __SRVNOTIFY__
