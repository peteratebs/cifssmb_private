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
#ifndef include_smbutils
#define include_smbutils

#include <algorithm>
#include <climits>
#include "smbdefs.h"

#define dualstringdecl(STRINGNAME) std::auto_ptr<dualstring> STRINGNAME(new(dualstring))
#define ENSURECSTRINGSAFETY(S) S=S?(byte *)S:(byte *)""

#define LARGEST_STRING 255

// string container can be intialized with ascii or utf16 and then be dereferenced by either type utf16() or the ascii() methods.
// Uses dynamic memory so use dualstringdecl(stringname) to ensure that the destrcutor is called to free memory.
class dualstring {
public:
  dualstring(int _maxlen=LARGEST_STRING) {buflen=0;maxlen=_maxlen; utf16view=0; asciiview=0;};
  ~dualstring() { if (utf16view) delete utf16view; if (asciiview) delete asciiview; };
//  word *utf16() { return (word *)((wchar_t *)utf16view.c_str()); }
  byte *ascii()  { return (byte *) asciiview;}
  word  *utf16() { return utf16view;}
  int   input_length() { return inlen; }
  bool  istoolong() {return (inlen > maxlen);}
  void operator =(byte *s)  {utf16view = new(word[arglen(s)+1]); asciiview = new(byte[buflen+1]); asciiview[buflen]=0; utf16view[buflen]=0; for (int i=0;i<buflen; i++) {asciiview[i]=(byte)s[i];utf16view[i]=(word)s[i];utf16view[i+1]=0;asciiview[i+1]=0;}}
  void operator =(word *s)  {utf16view = new(word[arglen(s)+1]); asciiview = new(byte[buflen+1]); asciiview[buflen]=0; utf16view[buflen]=0; for (int i=0;i<buflen; i++) {asciiview[i]=(byte)s[i];utf16view[i]=(word)s[i];utf16view[i+1]=0;asciiview[i+1]=0;}}
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
