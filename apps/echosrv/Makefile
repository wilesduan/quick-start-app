include ../../common.mk

INCLUDE= -I./src $(ALL_INCLUDES)
LIBS=$(ALL_LIBS)

CODE_GEN_BUILD_PATH=$(BUILD_OBJ_PATH)/apps/echosrv
SOURCE=$(wildcard ./src/*.cc) 
CODE_GEN_DIR=$(dir $(SOURCE))
CODE_GEN_OBJ_DIR=$(sort $(patsubst %, $(CODE_GEN_BUILD_PATH)/%, $(CODE_GEN_DIR)))
CODE_GEN_OBJ=$(patsubst %.cc, $(CODE_GEN_BUILD_PATH)/%.o, $(SOURCE)) 
CODE_GEN_BIN=$(BUILD_BIN_PATH)/echosrv


all:show_version dir $(CODE_GEN_BIN)

show_version:
	@echo
	@echo $(VERSION_STR)
	@echo


dir:
	mkdir -p $(CODE_GEN_OBJ_DIR) $(BUILD_BIN_PATH) $(BUILD_BIN_PATH)/../tgz/

$(CODE_GEN_BIN):$(CODE_GEN_OBJ) $(LIBS)
	$(CXX) -o $@ $^ $(LIBS)
	mkdir -p echosrv/bin echosrv/admin echosrv/conf
	cp $(CODE_GEN_BIN) echosrv/bin
	cp ./conf/* echosrv/conf/
	cp ./conf/echosrv.json$(CFG_POSTFIX) echosrv/conf/echosrv.json
	cd echosrv && tar cvzf echosrv.tgz admin bin conf
	mv echosrv/echosrv.tgz $(BUILD_BIN_PATH)/../tgz/
	rm -fr echosrv/

$(CODE_GEN_BUILD_PATH)/%.o : %.cc 
	$(CXX) --std=c++0x -o $@ $(CC_FLAGS) -c $< 
	
test: test_send_msg
test_send_msg: ./test/test_send_msg.cc
	$(CXX) -o ./test/test_send_msg.test $(CC_FLAGS) $^ $(LIBS)

clean:
	rm -fr $(CODE_GEN_OBJ) $(CODE_GEN_BIN) ./test/*.o ./test/*.test

install:
	mkdir -p $(INSTALL_PATH)/echosrv
	cp $(BUILD_BIN_PATH)/../tgz/echosrv.tgz $(INSTALL_PATH)/echosrv/
	cd $(INSTALL_PATH)/echosrv&& tar xzvf echosrv.tgz

