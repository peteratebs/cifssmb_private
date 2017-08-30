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
#include <string>

typedef char * warning_string_t;

inline void free_warning(warning_string_t &warning_string) { cout << *warning_string << endl; rtp_free(warning_string);}

class smb_diagnostics {
public:
  smb_diagnostics() {
    buffer = (char *)rtp_malloc_auto_freed(2048); // Manually freed in detructor since. Should use private local_allocator instead
    _p_diaglevel=DIAG_DISABLED;
    }
  ~smb_diagnostics() {
     std::for_each (warnings.begin(), warnings.end(), free_warning);
     rtp_free_auto_free(buffer);}

  void set_diag_level(smb_diaglevel diaglevel) { _p_diaglevel =diaglevel;}


  void diag_dump_unicode(smb_diaglevel at_diaglayer, const char *prompt, byte *buffer, int size)
  {
    if (_p_diaglevel && _p_diaglevel >= at_diaglayer)
    {
      rtsmb_dump_bytes(prompt, buffer, size, DUMPUNICODE);
    }
  }
  void diag_dump_bin(smb_diaglevel at_diaglayer, const char *prompt, byte *buffer, int size)
  {
    cout << prompt << endl;
    if (_p_diaglevel && _p_diaglevel >= at_diaglayer)
    {
      rtsmb_dump_bytes(prompt, buffer, size, DUMPBIN);
    }
  }
  void diag_dump_bin(smb_diaglevel at_diaglayer,  const char *prompt, word *buffer, int size)   { diag_dump_bin(at_diaglayer, prompt, (byte *)buffer, size); }
  void diag_dump_bin(smb_diaglevel at_diaglayer,  const char *prompt, void *buffer, int size)   { diag_dump_bin(at_diaglayer, prompt, (byte *)buffer, size); }

  void display_text_warnings()
  {
     for (int i = 0; i <  warnings.size(); i++)
     {
        diag_printf_fn(DIAG_INFORMATIONAL,"Warning: %s\n", warnings[i]);
        free(warnings[i]);
     }
     warnings.clear();
  }

  void diag_text_warning(const char* fmt...)
  {
      va_list args;
      va_start(args, fmt);
      vsprintf (buffer,fmt, args);
      warnings.push_back(rtsmb_strmalloc((char *)buffer));
      // Store this in a vector
      // cout << "warning: " << buffer << endl;
      va_end(args);
  }
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
  std::vector<warning_string_t> warnings;

};

#endif // include_smb2diagnostics
