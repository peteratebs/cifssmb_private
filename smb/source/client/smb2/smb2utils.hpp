//
// smbutils.hpp -
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
#ifndef include_smb2utils
#define include_smb2utils





#include <algorithm>
#include <climits>
#include <map>
#include <algorithm>
#include <iostream>
#include <string>
#include <memory>

using std::cout;
using std::endl;

// Log levels for further processing by cout_log()
#define LL_JUNK  0
#define LL_TESTS 1
#define LL_INIT  2
// Macro for now but convert to a class for a better outcome
#define cout_log(level) cout

#define dualstringdecl(STRINGNAME) std::auto_ptr<dualstring> STRINGNAME(new(dualstring))
#define LARGEST_STRING 255

/// dualstring string container can be intialized with ascii or utf16 and then be dereferenced by either type utf16() or the ascii() methods.
/// Uses dynamic memory so use dualstringdecl(stringname) to ensure that the destrcutor is called to free memory.
class dualstring {
public:
  dualstring(int _maxlen=LARGEST_STRING) {buflen=0;maxlen=_maxlen; utf16view=0; asciiview=0;};
  ~dualstring() { if (utf16view) rtp_free(utf16view); if (asciiview) rtp_free(asciiview); };
//  word *utf16() { return (word *)((wchar_t *)utf16view.c_str()); }
  byte *ascii()  { return (byte *) asciiview;}
  word  *utf16() { return utf16view;}
  int   input_length() { return inlen; }
  bool  istoolong() {return (inlen > maxlen);}
  void operator =(byte *s)  {utf16view = (word *)rtp_malloc(2*(arglen(s)+1)); asciiview = (byte *)rtp_malloc(buflen+1); asciiview[buflen]=0; utf16view[buflen]=0; for (int i=0;i<buflen; i++) {asciiview[i]=(byte)s[i];utf16view[i]=(word)s[i];utf16view[i+1]=0;asciiview[i+1]=0;}}
  void operator =(word *s)  {utf16view = (word *)rtp_malloc(2*(arglen(s)+1)); asciiview = (byte *)rtp_malloc(buflen+1); asciiview[buflen]=0; utf16view[buflen]=0; for (int i=0;i<buflen; i++) {asciiview[i]=(byte)s[i];utf16view[i]=(word)s[i];utf16view[i+1]=0;asciiview[i+1]=0;}}
private:
  int maxlen;
  int buflen;
  int inlen;
  int arglen(byte *s)  { inlen=0; buflen=0; while(s[inlen++]);  buflen = std::min(inlen,maxlen); return buflen; }
  int arglen(word *s)  { inlen=0; buflen=0; while(s[inlen++]); buflen = std::min(inlen,maxlen); return buflen;}
  word *utf16view;
  byte *asciiview;
};



#endif // include_smbutils
