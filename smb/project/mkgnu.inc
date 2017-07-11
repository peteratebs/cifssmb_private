# This file evaluates the variables set on the command line and acts on them.
# targ is set to something such as POLG68K, RTPXMSP3, etc.
# RELENV should be N for ebsenv, Y otherwise.
# v=v for debug, v=o for optimized.

########################################################################
targ = LINUX

# set the following to "Y" for RTUPnP, "N" otherwise.
dortupnp = "Y"

# set the following to "Y" to include nbns functions like browser announcements etc.
donbserver = "N"

########################################################################

root    = ..
kernel  = c:

#source path
lib_to_rtsmb2_common_path     = $(SMB_PATH)/source/smb2_common
lib_to_rtsmb_crypto_path      = $(SMB_PATH)/source/crypto
lib_to_rtsmb_common_path      = $(SMB_PATH)/source/common
lib_to_rtsmb_commonnb_path    = $(SMB_PATH)/source/commonnb
lib_to_rtsmb_server_path      = $(SMB_PATH)/source/server
lib_to_rtsmb_nbserver_path    = $(SMB_PATH)/source/servernb
lib_to_rtsmb_server_demo_path = $(SMB_PATH)/source/serverexample
lib_to_rtsmb_client_path      = $(SMB_PATH)/source/client
lib_to_rtsmb_boostclient_path = $(SMB_PATH)/source/boostclient
lib_to_rtsmb_client_demo_path = $(SMB_PATH)/demo
#clib_to_rtsmb_client_demo_path = $(SMB_PATH)/source/clientexample
lib_to_rtptarget              = $(SMB_PATH)/../rtplatform/source/linux
lib_to_rtpgeneric             = $(SMB_PATH)/../rtplatform/source/generic

#include path
lib_to_rtsmb2_common_include   = $(SMB_PATH)/source/smb2_common
lib_to_rtsmb2_server_include   = $(SMB_PATH)/source/smb2_server
lib_to_rtsmb_boostclient_include = $(SMB_PATH)/source/boostclient
lib_to_rtsmb_crypto_include      = $(SMB_PATH)/source/crypto
lib_to_rtsmb_common_include   = $(SMB_PATH)/source/common
lib_to_rtsmb_commonnb_include = $(SMB_PATH)/source/commonnb
lib_to_rtsmb_server_include   = $(SMB_PATH)/source/server
lib_to_rtsmb_nbserver_include = $(SMB_PATH)/source/servernb
lib_to_rtsmb_client_include   = $(SMB_PATH)/source/client
lib_to_rtptarget_include      = $(SMB_PATH)/../rtplatform/include/linux
lib_to_rtpgeneric_include     = $(SMB_PATH)/../rtplatform/include

########################################################################

known = "N"

ifeq ($(targ),LINUX)
known = "Y"
# Set the compiler type for later conditionals
compiler = GNUCOMPILER
# pointersize = P64
pointersize = P32
endif

ifneq ($(known),"Y")
.PHONY: error
error:
ifneq ($(targ),)
	@echo Incorrect target: $(targ)
else
	@echo Please set the targ and v variables.
endif
	@echo Please edit
endif

########################################################################

ifeq ($(compiler),GNUCOMPILER)
# Set the file extensions
obj = o
lib = a
exe = out
endif

############################ THE END ###################################
