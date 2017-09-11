#include $(targ).inc


DEBUG=1

# Compiler flag for debugging purposes
ifdef DEBUG
   ifeq ($(DEBUG),1)
       cflags  += -g
       ccflags += -g
       ldflags += -g
   endif
else
   cflags +=
   ccflags +=
   ldflags +=
endif

# pointersize = P32

ifeq ($(pointersize),P32)
### COMPILER AND LINKER FLAGS ########################################

# ldflags += -m32 -L/usr/lib/i386-linux-gnu -L/usr/lib32 -lm -lc -lgcc  -pthread -lboost_thread -lboost_system -Wl,-Map=output.map
ldflags += -lmcheck -m32 -L/usr/lib/i386-linux-gnu -L/usr/lib32 -lm -lc -lgcc  -pthread -Wl,-Map=output.map

# cflags  += -Wconversion -Wextra -Werror
cflags  += -m32 -pthread -DBUILD_SMB_32BIT
cflags  += -D_FILE_OFFSET_BITS=64
# cflags  += -m64 -DBUILD_SMB_64BIT
endif

ifeq ($(pointersize),P64)
### COMPILER AND LINKER FLAGS ########################################
ldflags += -m64 -L/usr/lib64  -lm -lc -lgcc -pthread -Wl,-Map=output.map
cflags  +=  -fpack-struct=1 -m64 -pthread -DBUILD_SMB_64BIT
# cflags  += -m64 -DBUILD_SMB_64BIT
endif

cflags  += -Wall -Wno-unused-parameter -Wno-unused-variable

#   cflags  += -Wall -Werror -Wextra

######################################################################

### CREATING AN OBJ DIRECTORY ########################################
ifndef $(OBJDIR)
	OBJDIR=./bin
endif
#### Creating an output directory
$(shell mkdir $(OBJDIR))

######################################################################

### RULES ############################################################
ifeq ($(compiler),GNUCOMPILER)
%.$(lib):
	echo ARCHIVING $@ $^
	@ar ru $@ $^


$(OBJDIR)/%.$(obj): %.cpp
	@echo rule based COMPILING for CPP $<
	@g++ -x c++ $(cflags)  $(defines:%=-D%) $(includes:%=-I%) -c $<	-o $(OBJDIR)/$(notdir $@)

ifeq ($(doclient),"Y")
include ../clientrulesgnu.inc
else
include ../serverrulesgnu.inc
endif
# bin/srvssn.o: $(lib_to_rtsmb_server_path)/srvssn.c
$(OBJDIR)/srvobjects.o: $(lib_to_rtsmb_server_path)/srvobjects.c
	@echo COMPILING for CPP $<
	@g++ -x c++ $(cflags)  $(defines:%=-D%) $(includes:%=-I%) -c $<	-o $(OBJDIR)/$(notdir $@)

$(OBJDIR)/srvsmbssnoo.o: $(lib_to_rtsmb_server_path)/srvsmbssnoo.cpp
	@echo COMPILING for CPP $<
	@g++ -x c++ $(cflags) $(defines:%=-D%) $(includes:%=-I%) -c $<	-o $(OBJDIR)/$(notdir $@)


$(OBJDIR)/srvsmbssn.o: $(lib_to_rtsmb_server_path)/srvsmbssn.cpp
	@echo COMPILING for CPP $<
	@g++ -x c++ $(cflags) $(defines:%=-D%) $(includes:%=-I%) -c $<	-o $(OBJDIR)/$(notdir $@)


$(OBJDIR)/srvoplocks.o: $(lib_to_rtsmb_server_path)/srvoplocks.cpp
	@echo COMPILING for CPP $<
	@g++ -x c++ $(cflags) $(defines:%=-D%) $(includes:%=-I%) -c $<	-o $(OBJDIR)/$(notdir $@)

$(OBJDIR)/%.$(obj): %.c
	@echo COMPILING $<
	@gcc	$(cflags) -Wno-pointer-sign $(defines:%=-D%) $(includes:%=-I%) -c $<	-o $(OBJDIR)/$(notdir $@)

#$(OBJDIR)/%.$(obj): %.cpp
#	@echo cpp COMPILING $<
#	@gcc	$(cflags) $(defines:%=-D%) $(includes:%=-I%) -c $<	-o $(OBJDIR)/$(notdir $@)

ifeq ($(buildtarget),server)
%.$(exe):
	@echo LINKING $@
	@echo LINKING $@  $(ldflags) -o $(notdir $@) $^ -lstdc++
	gcc $(ldflags) -o $(notdir $@) $^ -lstdc++
else
%.$(exe):
	@echo LINKING $@
	@echo LINKING $@  $(ldflags) -o $(notdir $@) $^ -lstdc++ -lboost_thread -lboost_system
	g++ $(ldflags) -o $(notdir $@) $^ -lstdc++ -lboost_thread -lboost_system
endif

endif #	GNUCOMPILER

#######################################################################

#### GENERIC STUFF ####################################################


# Make the web page	files
#%.c %.h: %.htm	%.cla
#	echo BINTOC	$<
#	../webpage/bintoc $(subst /,\\,$<) $(subst /,\\,$(basename $(notdir	$<)))

# Make dependency files
%.d: %.c
	echo UPDATING DEPENDENCIES FOR $<
	gcc	-undef -M $< $(defines:%=-D%) $(builtins:%=-D%)	$(includes:%=-I%) |	depend $(obj) >	$@

# Make dependency files
%.d: %.cpp
	echo UPDATING DEPENDENCIES FOR $<
	gcc	-undef -M $< $(defines:%=-D%) $(builtins:%=-D%)	$(includes:%=-I%) |	depend $(obj) >	$@

.INTERMEDIATE: $(modules:%=%.d)
$(targ).inc: $(modules:%=%.d)
	echo MAKING	$@
	cat	*.d	> $@

### CLEANING ###########################################################
.PHONY:	CLEAN
CLEAN:
	echo CLEANING
	rm -rf	$(OBJDIR)/*
	rm -rf   *.o
	rm -rf	*.a
	rm -rf   *.out

.PHONY:	clean
clean:
	echo CLEANING
	rm -rf	$(OBJDIR)/*
	rm -rf   *.o
	rm -rf	*.a
	rm -rf   *.out


.PHONY:	dep
dep:
	echo DEPENDENCIES UPDATED

###################### THE END ##########################################
