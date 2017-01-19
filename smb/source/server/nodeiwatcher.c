#include "srvapi.h"
#include "smbdebug.h"
#include "rtpprint.h"
#include "rtpterm.h"
#include "psmbfile.h"
#include "rtpscnv.h"
#include "rtpthrd.h"
#include "srvobjectsc.h"
#include "remotediags.h"
#include "srvcfg.h"
#include "srvutil.h"
#include "rtpmem.h"

#include <sys/inotify.h>
#include <limits.h>
#include <unistd.h>


// #include "tlpi_hdr.h"

oplock_diagnotics_t oplock_diagnotics;

extern volatile int go; /* Variable loop on.. Note: Linux version needs sigkill support to clean up */

static void displayInotifyEvent(struct inotify_event *i)
{
    printf("    wd =%2d; ", i->wd);
    if (i->cookie > 0)
        printf("cookie =%4d; ", i->cookie);

    printf("mask = ");
    if (i->mask & IN_ACCESS)        printf("IN_ACCESS ");
    if (i->mask & IN_ATTRIB)        printf("IN_ATTRIB ");
    if (i->mask & IN_CLOSE_NOWRITE) printf("IN_CLOSE_NOWRITE ");
    if (i->mask & IN_CLOSE_WRITE)   printf("IN_CLOSE_WRITE ");
    if (i->mask & IN_CREATE)        printf("IN_CREATE ");
    if (i->mask & IN_DELETE)        printf("IN_DELETE ");
    if (i->mask & IN_DELETE_SELF)   printf("IN_DELETE_SELF ");
    if (i->mask & IN_IGNORED)       printf("IN_IGNORED ");
    if (i->mask & IN_ISDIR)         printf("IN_ISDIR ");
    if (i->mask & IN_MODIFY)        printf("IN_MODIFY ");
    if (i->mask & IN_MOVE_SELF)     printf("IN_MOVE_SELF ");
    if (i->mask & IN_MOVED_FROM)    printf("IN_MOVED_FROM ");
    if (i->mask & IN_MOVED_TO)      printf("IN_MOVED_TO ");
    if (i->mask & IN_OPEN)          printf("IN_OPEN ");
    if (i->mask & IN_Q_OVERFLOW)    printf("IN_Q_OVERFLOW ");
    if (i->mask & IN_UNMOUNT)       printf("IN_UNMOUNT ");
    printf("\n");

    if (i->len > 0)
        printf("        name = %s\n", i->name);
}

// For each wd
//   If it is being watched
//      Test mask
//      If Mask
//        close current stream if open
//        open stream if not open
//        add mask to stream
//      close current stream if open



#define BUF_LEN (10 * (sizeof(struct inotify_event) + NAME_MAX + 1))
static int inotifyFd;

static int SendInotifyEventToRtsmb(struct inotify_event *event)
{
uint32_t mapped_masked = 0;
    printf("    wd =%2d; ", event->wd);
    //if (find_notify_request_from_alert(event->wd))
    //  ;
    if (event->mask & IN_ATTRIB)
       mapped_masked |=  FILE_ACTION_MODIFIED           ;        // The file was modified. This may be a change to the data or attributes of the file.
    if (event->mask & IN_CLOSE_WRITE)
      mapped_masked |=  FILE_ACTION_MODIFIED           ;        // The file was modified. This may be a change to the data or attributes of the file.
    if (event->mask & IN_CREATE)
      mapped_masked |=  FILE_ACTION_ADDED              ;        // The file was added to the directory.
    if (event->mask & IN_DELETE)
    {
       mapped_masked |=  FILE_ACTION_REMOVED            ;        // The file was removed from the directory.
       // mapped_masked |=  FILE_ACTION_REMOVED_BY_DELETE  ;        // The file was removed by delete.
    }
    if (0 && event->mask & IN_DELETE_SELF)
    {
       mapped_masked |=  FILE_ACTION_REMOVED            ;        // The file was removed from the directory.
       // mapped_masked |=  FILE_ACTION_REMOVED_BY_DELETE  ;        // The file was removed by delete.
    }
    if (event->mask & IN_MODIFY)
      mapped_masked |=  FILE_ACTION_MODIFIED           ;        // The file was modified. This may be a change to the data or attributes of the file.
//    if (event->mask & IN_MOVE_SELF)
    if (event->mask & IN_MOVED_FROM)
      mapped_masked |=  FILE_ACTION_RENAMED_OLD_NAME   ;        // The file was renamed, and this is the old name. If the new name resides within the directory being monitored, the client will also receive the FILE_ACTION_RENAMED_NEW_NAME bit value as described in the next list item. If the new name resides outside of the directory being monitored, the client will not receive the FILE_ACTION_RENAMED_NEW_NAME bit value.
    if (event->mask & IN_MOVED_TO)
      mapped_masked |=  FILE_ACTION_RENAMED_NEW_NAME   ;        // The file was renamed, and this is the new name. If the old name resides within the directory being monitored, the client will also receive the FILE_ACTION_RENAME_OLD_NAME bit value. If the old name resides outside of the directory being monitored, the client will not receive the FILE_ACTION_RENAME_OLD_NAME bit value.

#if (0)
    mapped_masked = 0;
    if (event->mask & IN_CREATE)
      mapped_masked |=  FILE_ACTION_ADDED              ;        // The file was added to the directory.
    if (event->mask & IN_DELETE)
    {
       mapped_masked |=  FILE_ACTION_REMOVED            ;        // The file was removed from the directory.
       // mapped_masked |=  FILE_ACTION_REMOVED_BY_DELETE  ;        // The file was removed by delete.
    }
#endif

    if (mapped_masked)
    {
       RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:SendInotifyEventToRtsmb mask: %lu\n", mapped_masked);
       send_notify_request_from_alert(event->wd,event->name, mapped_masked);
       return 1;
    }
     // if (find_notify_request_from_alert(event->wd,event->name, mapped_masked))
    return 0;
}


static void doWatch(void)
{
char buf[BUF_LEN] __attribute__ ((aligned(8)));
ssize_t numRead;
  char *p;
  struct inotify_event *event;

  inotifyFd = inotify_init();                 /* Create inotify instance */
  if (inotifyFd == -1)
      srvsmboo_panic("inotify_init");
    while (go) {                                  /* Read events forever */
        numRead = read(inotifyFd, buf, BUF_LEN);
//        numRead = read(inotifyFd, buf, BUF_LEN);
        if (numRead == 0)
            srvsmboo_panic("read() from inotify fd returned 0!");

        if (numRead == -1)
            srvsmboo_panic("read");

        printf("Read %ld bytes from inotify fd\n", (long) numRead);
        /* Process all of the events in buffer returned by read() */
//        for (p = buf; p < buf + numRead; ) {
//            event = (struct inotify_event *) p;
//            displayInotifyEvent(event);
//            p += sizeof(struct inotify_event) + event->len;
//        }
        for (p = buf; p < buf + numRead; ) {
            event = (struct inotify_event *) p;
            if (SendInotifyEventToRtsmb(event))
            {
              displayInotifyEvent(event);
              break;  // Try only sending one message
            }
            p += sizeof(struct inotify_event) + event->len;
        }
    }
}
void rtsmb_thread_iwatch (void *p)
{
  doWatch();
}

  /* For each command-line argument, add a watch for all events */

#define IN_ALL_MY_EVENTS	(IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | \
			 IN_MOVED_FROM | \
			 IN_MOVED_TO | IN_DELETE | IN_CREATE | IN_DELETE_SELF)

void linux_inotify_add_watch(const char *pathname, uint32_t mask)
{
uint32_t linux_mask;
  if (mask)
  {
    linux_mask =
//    IN_ONESHOT|
//    IN_ACCESS|
    IN_ATTRIB|
    IN_CREATE|
    IN_DELETE|
    IN_DELETE_SELF|
//    IN_ISDIR|
    IN_MODIFY|
    IN_CLOSE_WRITE|
//    IN_MOVE_SELF|
    IN_MOVED_FROM|
    IN_MOVED_TO|
    IN_OPEN;
//    IN_Q_OVERFLOW|
 //   IN_UNMOUNT|

    linux_mask = IN_ALL_MY_EVENTS;
    int wd = inotify_add_watch(inotifyFd, pathname, linux_mask);
    if (wd == -1)
      srvsmboo_panic("inotify_add_watch");
  }
  else
  {
    ;//      int inotify_rm_watch(int fd, int wd);
  }
}


void linux_inotify_cancel_watch(int wd)
{
  inotify_rm_watch(inotifyFd, wd);

}
