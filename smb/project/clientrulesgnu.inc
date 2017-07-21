
$(OBJDIR)/%.$(obj): $(lib_to_rtsmb_client_path)/%.cpp $(clienthpfiles)
#$(OBJDIR)/%.$(obj): $(lib_to_rtsmb_client_path)/%.cpp
	@echo COMPILING SMB2 CLIENT CODE for CPP $<
	@echo List is $(clienthpfiles)
	@g++ -x c++ $(cflags)  $(defines:%=-D%) $(includes:%=-I%) -c $<	-o $(OBJDIR)/$(notdir $@)


$(OBJDIR)/%.$(obj): $(lib_to_rtsmb_boostclient_path)/%.cpp
	@echo COMPILING BOOST CLIENT for CPP $<
	@g++ -x c++ $(cflags)  $(defines:%=-D%) $(includes:%=-I%) -c $<	-o $(OBJDIR)/$(notdir $@)
