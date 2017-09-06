
$(OBJDIR)/%.$(obj): $(lib_to_rtsmb2_ooserver_path)/%.cpp $(serverhpfiles)
#$(OBJDIR)/%.$(obj): $(lib_to_rtsmb_client_path)/%.cpp
	@echo TROMPILING SMB2 SERVER CODE for CPP $<
	@echo includes $(includes)
	@echo lib_to_rtsmb2_oocommon_path $(lib_to_rtsmb2_oocommon_path)
	@echo List is $(clienthpfiles)
	@g++ -x c++ $(cflags)  $(defines:%=-D%) $(lib_to_rtsmb2_oocommon_path:%=-I%) $(includes:%=-I%) -c $<	-o $(OBJDIR)/$(notdir $@)

$(OBJDIR)/%.$(obj): $(lib_to_rtsmb2_oocommon_path)/%.cpp $(serverhpfiles)
	@echo SNOMPILING SMB2 SERVER CODE for CPP $<
	@echo inludes $(includes)
	@echo inludes $(includes) g++ -x c++ $(cflags)  $(defines:%=-D%) $(lib_to_rtsmb2_oocommon_path:%=-I%) $(includes:%=-I%) -c $<	-o $(OBJDIR)/$(notdir $@)
	@g++ -x c++ $(cflags)  $(defines:%=-D%) $(lib_to_rtsmb2_oocommon_path:%=-I%) $(includes:%=-I%) -c $<	-o $(OBJDIR)/$(notdir $@)
