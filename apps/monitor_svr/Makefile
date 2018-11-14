include ../../common.mk

INCLUDE= -I./src $(ALL_INCLUDES) 
LIBS=$(ALL_LIBS) 

CODE_GEN_BUILD_PATH=$(BUILD_OBJ_PATH)/apps/monitor_svr
SOURCE=$(wildcard ./src/*.cc) 
CODE_GEN_DIR=$(dir $(SOURCE))
CODE_GEN_OBJ_DIR=$(sort $(patsubst %, $(CODE_GEN_BUILD_PATH)/%, $(CODE_GEN_DIR)))
CODE_GEN_OBJ=$(patsubst %.cc, $(CODE_GEN_BUILD_PATH)/%.o, $(SOURCE)) 
CODE_GEN_BIN=$(BUILD_BIN_PATH)/monitor_svr


all:show_version dir $(CODE_GEN_BIN) 

show_version:
	@echo
	@echo $(VERSION_STR)
	@echo


dir:
	mkdir -p $(CODE_GEN_OBJ_DIR) $(BUILD_BIN_PATH) $(BUILD_BIN_PATH)/../tgz/

$(CODE_GEN_BIN):$(CODE_GEN_OBJ) $(LIBS)
	$(CXX) -o $@ $^ $(LIBS)
	mkdir -p monitor_svr/bin monitor_svr/admin monitor_svr/conf
	cp $(CODE_GEN_BIN) monitor_svr/bin
	cp ./conf/* monitor_svr/conf/
	cp ./conf/monitor_svr.json$(CFG_POSTFIX) monitor_svr/conf/monitor_svr.json
	cd monitor_svr && tar cvzf monitor_svr.tgz admin bin conf
	mv monitor_svr/monitor_svr.tgz $(BUILD_BIN_PATH)/../tgz/
	rm -fr monitor_svr/

$(CODE_GEN_BUILD_PATH)/%.o : %.cc 
	$(CXX) -std=c++11 -o $@ $(CC_FLAGS) -c $< 
	
clean:
	rm -fr $(CODE_GEN_OBJ) $(CODE_GEN_BIN) 

install:
	mkdir -p $(INSTALL_PATH)/monitor_svr
	cp $(BUILD_BIN_PATH)/../tgz/monitor_svr.tgz $(INSTALL_PATH)/monitor_svr/
	cd $(INSTALL_PATH)/monitor_svr&& tar xzvf monitor_svr.tgz

