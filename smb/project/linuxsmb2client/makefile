# GNU Makefile for RTSMB Client Application

### Usage ##############################################################
### :make clean
### :make
### :make DEBUG=1              ------------------ For debugging purposes
########################################################################
incpath = .

doclient = "Y"

cflags += -D SUPPORT_SMB2 -D BUILDING_CLIENT

## SET SMB_PATH for mkgnu to find it
HTTP_PATH = ../../../../http/v0.2.6
SMB_PATH  = ../../../smb


include ../mkgnu.inc

includes = $(lib_to_rtptarget_include) $(lib_to_rtpgeneric_include) $(lib_to_rtsmb2_client_include) $(lib_to_rtsmb2_oocommon_path) $(lib_to_rtsmb2_ooclient_path)





########################################################################
# SOURCE PATHS
########################################################################


vpath %.c   . $(app_to_RTSMB_path) $(lib_to_rtsmb2_ooclient_path) $(lib_to_rtptarget) $(lib_to_rtpgeneric) $(lib_to_rtsmb_client_demo_path)

vpath %.h   . $(lib_to_rtsmb2_client_include) $(lib_to_rtptarget_include) $(lib_to_rtpgeneric_include)

########################################################################
# OPERATING SYSTEM/ENVIRONMENT SPECIFIC MODULES
########################################################################
# The only files that should go here are files that are specific to one
# particular target, operating system, compiler, etc. and must go into
# the library.  Make sure your conditional(s) are as general as possible.

ifeq ($(os),LINUX)
#modules +=
endif

########################################################################
# EBS PACKAGES
########################################################################

ifeq ($(dortsmb),"Y")
defines +=
endif

defines += BOOST_SYSTEM_NO_DEPRECATED


#############################################################################
# SETUP
#############################################################################

# The basic required list of modules, defines, includes.

# clean up the modules, includes, defines
# dirs = $(lib_to_webc_path)

# rtsmb client build
#  includes += $(lib_to_rtsmb2_client_include) $(lib_to_rtsmb2_oocommon_path) $(lib_to_rtsmb2_client_include) $(lib_to_rtsmb2_oocommon_path)
dirs = $(lib_to_rtsmb2_ooclient_path) $(lib_to_rtsmb2_oocommon_path) $(lib_to_rtsmb_client_demo_path)

## Note: debug dynamic allocation for client
#defines += ALLOC_FROM_HEAP


#RTSMB COMMON FILES USED


# These shouldn't be linked if NBNS support is disabled,, need to fix

#RTSMB CLIENT FILES USED

clienthpfiles := $(wildcard $(lib_to_rtsmb2_ooclient_path)/*.hpp) $(wildcard $(lib_to_rtsmb2_oocommon_path)/*.hpp)
hpdependlist := $(hpfiles)

# cpfiles := $(wildcard $(lib_to_rtsmb2_ooclient_path)/*.cpp) $(wildcard $(lib_to_rtsmb2_oocommon_path)/*.cpp)

cpfiles := $(foreach dir,$(dirs),$(wildcard $(dir)/*.cpp))
# cpfiles += $(lib_to_rtsmb2_oocommon_path)/hmacsha256.cpp


cpmodules := $(patsubst %.cpp,%,$(cpfiles))


#RTSMB EXAMPLE FILES USED


#RTPLATFORM FILES USED
cfiles += $(lib_to_rtpgeneric)/rtpchar.c
cfiles += $(lib_to_rtpgeneric)/rtpmtxdb.c
cfiles += $(lib_to_rtpgeneric)/rtprand.c
cfiles += $(lib_to_rtpgeneric)/rtprot.c
cfiles += $(lib_to_rtpgeneric)/rtpstr.c
cfiles += $(lib_to_rtpgeneric)/rtpscnv.c
cfiles += $(lib_to_rtpgeneric)/rtpwchar.c
cfiles += $(lib_to_rtpgeneric)/rtpwcs.c
cfiles += $(lib_to_rtpgeneric)/rtpwscnv.c
cfiles += $(lib_to_rtpgeneric)/rtphelper.c
cfiles += $(lib_to_rtpgeneric)/rtpdutil.c
cfiles += $(lib_to_rtpgeneric)/rtplog.c
cfiles += $(lib_to_rtptarget)/rtpdate.c
cfiles += $(lib_to_rtptarget))/rtpdebug.c
cfiles += $(lib_to_rtptarget)/rtpdobj.c
cfiles += $(lib_to_rtptarget)/rtpfile.c
cfiles += $(lib_to_rtptarget)/rtpmem.c
cfiles += $(lib_to_rtptarget)/rtpnet.c
cfiles += $(lib_to_rtptarget)/rtpsignl.c
cfiles += $(lib_to_rtptarget)/rtpterm.c
cfiles += $(lib_to_rtptarget)/rtpthrd.c
cfiles += $(lib_to_rtptarget)/rtptime.c
cfiles += $(lib_to_rtptarget)/rtpwfile.c


cmodules := $(patsubst %.c,%,$(cfiles))

modules += $(cpmodules)
modules += $(cmodules)

modules  := $(sort $(modules))
#includes := $(sort $(includes))
defines  := $(sort $(defines))

# now set up the object list
blah1 = $(modules:%=%.$(obj))
objects = $(notdir $(blah1))
OBJDIR=./bin
OUT_OBJS = $(addprefix $(OBJDIR)/,$(objects))

#############################################################################
# RULES
#############################################################################
all: rtsmbclientapplication.out

$(OBJDIR)/rtsmbclientlib.a: $(OUT_OBJS)

$(OBJDIR)/rtsmbclientapplication.o: rtsmbclientapplication.cpp

$(OBJDIR)/boostclientconsole.o: $(lib_to_rtsmb_boostclient_path)/boostclientconsole.cpp

$(OBJDIR)/boostclientcontrol.o: $(lib_to_rtsmb_boostclient_path)/boostclientcontrol.cpp



rtsmbclientapplication.out: $(OBJDIR)/rtsmbclientapplication.o $(OBJDIR)/boostclientconsole.o $(OBJDIR)/boostclientcontrol.o $(OBJDIR)/rtsmbclientlib.a

not_all:
	echo $(vpathXXX)


include ../rulesgnu.inc
#############################################################################
