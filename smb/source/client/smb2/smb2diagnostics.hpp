//
// smb2diagnostics.hpp -
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

#ifndef include_smb2diagnostics
#define include_smb2diagnostics

#include <cstdarg>
#include <cstdio>

typedef enum smb_diaglevel_e {
    DIAG_DISABLED      =0,
    DIAG_JUNK          =1,             // Handy for bumping diagnostics.
    DIAG_INFORMATIONAL =2,
    DIAG_DEBUG         =3,
} smb_diaglevel;

class smb_diagnostics {
public:
  smb_diagnostics() {
    buffer = (char *)rtp_malloc_auto_freed(2048); // Manually freed in detructor since. Should use private local_allocator instead
    _p_diaglevel=DIAG_DISABLED;
    }
  ~smb_diagnostics() { rtp_free_auto_free(buffer);}

  void set_diag_level(smb_diaglevel diaglevel) { _p_diaglevel =diaglevel; cout << "Set level" << _p_diaglevel << endl; }
  void diag_dump_bin(smb_diaglevel at_diaglayer, const char *prompt, byte *buffer, int size)
  {
    cout << prompt << endl;
    cout << "Curr level: " << _p_diaglevel << "message level: "  << at_diaglayer << endl;
    if (_p_diaglevel && _p_diaglevel >= at_diaglayer)
    {
      rtsmb_dump_bytes(prompt, buffer, size, DUMPBIN);
    }
  }
  void diag_dump_bin(smb_diaglevel at_diaglayer,  const char *prompt, word *buffer, int size)   { diag_dump_bin(at_diaglayer, prompt, (byte *)buffer, size); }
  void diag_dump_bin(smb_diaglevel at_diaglayer,  const char *prompt, void *buffer, int size)   { diag_dump_bin(at_diaglayer, prompt, (byte *)buffer, size); }

 //  note: use %ls to display utf16
  void diag_printf(smb_diaglevel at_diaglayer, const char* fmt...)
  {
      va_list args;
      va_start(args, fmt);

      if (!_p_diaglevel || _p_diaglevel < at_diaglayer)
        return;
      else
      {
        vsprintf (buffer,fmt, args);
        diag_printbuffer();
      }
      va_end(args);
  }


private:
  void diag_printbuffer()     { cout << buffer; };
  char *buffer;
  smb_diaglevel _p_diaglevel;
};

#endif // include_smb2diagnostics
