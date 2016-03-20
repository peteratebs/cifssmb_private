#ifndef __SRVIPCFILE__
#define __SRVIPCFILE__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "psmbfile.h"

extern PSMBFILEAPI prtsmb_ipcrpc_filesys;
int rtsmb_ipcrpc_filesys_init(void);



#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SRVIPCFILE__ */
