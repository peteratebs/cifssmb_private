#ifndef __SRVNOTIFY__
#define __SRVNOTIFY__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// Message format sent over signal_port_number from OS to rtsmb to signal a notify event
typedef struct rtsmbNotifyMessage_s {
  uint16_t session_index;                          // From rtplatform_notify_request_args
  uint16_t notify_index;                           // From rtplatform_notify_request_args
  uint8_t  file_id[16];                            // From rtplatform_notify_request_args
  uint32_t payloadsize;                            // Number of bytes to follow, these will be appended to a notify alert message and send to the client
// Payload
}  __attribute__((packed)) rtsmbNotifyMessage;


// Structure used to pass notify requests to the OS
typedef struct rtplatform_notify_request_args_s {
  int      signal_port_number;                                              // UDP port number to send notify messages to on localhost
  uint16_t session_index;                                                   // small integer value 0 to MAX_SESSIONS to include in notify message
  uint16_t notify_index;                                                    // small integer value 0 to MAX_NOTIFIES_PER_SESSION  to include in notify message
  uint16_t smb_protocol;                                                    // SMB protocol, 1 or 2. TBD if preformatted replies are different
  uint16_t tid;                                                             //
  uint16_t Flags;                                                           //
  uint8_t  file_id[16];                                                     // 16 bit file ID, INODE number is encoded
  uint32_t max_notify_message_size;                                         // Maximum payload size to embed in notify messages
  uint32_t completion_filter;                                               // 0 means clear or others below.
  // Note: tbd: session_index:notify_index== N:0xffff && completion_filter == 0 could be used to clear all notifies for a session
}  rtplatform_notify_request_args;


typedef struct rtplatform_notify_control_object_s {
  rtplatform_notify_request_args args;  // Copy of the request
  size_t  next_location_offset;
  size_t  format_buffer_size;
  size_t  formatted_content_size;
  uint8_t *message_buffer; // Points to preformatted rtsmbNotifyMessage structure prior to format_buffer
  rtsmbNotifyMessage *pmessage; // Typed alias for message_buffer
  uint8_t *format_buffer;  // Copy of the request
} rtplatform_notify_control_object;

// API for rtsmb send a notify queue request or cancelation to the OS.
void rtplatform_notify_request(rtplatform_notify_request_args *prequest);

// API for the OS to queue up and send notifies
int notify_message_open(rtplatform_notify_control_object *phandle, rtplatform_notify_request_args *pargs, size_t maximimumsize);
int notify_message_append(rtplatform_notify_control_object *phandle, uint32_t change_alert_type, size_t utf_string_size, uint16_t *utf_16_string); // Null terminated UTF16 strings probably, returns -1 if message is too large
void notify_message_close(rtplatform_notify_control_object *phandle);
void notify_message_dispcard(rtplatform_notify_control_object *phandle);
void notify_message_send_and_release(rtplatform_notify_control_object *phandle);



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





#ifdef __cplusplus
}
#endif

#endif // __SRVNOTIFY__
