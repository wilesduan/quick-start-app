include ../../common.mk

INCLUDE= -I./src $(ALL_INCLUDES)
LIBS=$(ALL_LIBS)

CODE_GEN_BUILD_PATH=$(BUILD_OBJ_PATH)/apps/http_gw
SOURCE=$(wildcard ./src/*.cc) 
CODE_GEN_DIR=$(dir $(SOURCE))
CODE_GEN_OBJ_DIR=$(sort $(patsubst %, $(CODE_GEN_BUILD_PATH)/%, $(CODE_GEN_DIR)))
CODE_GEN_OBJ=$(patsubst %.cc, $(CODE_GEN_BUILD_PATH)/%.o, $(SOURCE)) 
CODE_GEN_BIN=$(BUILD_BIN_PATH)/http_gw


all:show_version dir $(CODE_GEN_BIN)

show_version:
	@echo
	@echo $(VERSION_STR)
	@echo


dir:
	mkdir -p $(CODE_GEN_OBJ_DIR) $(BUILD_BIN_PATH) $(BUILD_BIN_PATH)/../tgz/

$(CODE_GEN_BIN):$(CODE_GEN_OBJ) $(LIBS)
	$(CXX) -o $@ $^ $(LIBS)
	mkdir -p http_gw/bin http_gw/admin http_gw/conf
	cp $(CODE_GEN_BIN) http_gw/bin
	cp ./conf/* http_gw/conf/
	cp ./conf/http_gw.json$(CFG_POSTFIX) http_gw/conf/http_gw.json
	cd http_gw && tar cvzf http_gw.tgz admin bin conf
	mv http_gw/http_gw.tgz $(BUILD_BIN_PATH)/../tgz/
	rm -fr http_gw/

$(CODE_GEN_BUILD_PATH)/%.o : %.cc 
	$(CXX) --std=c++0x -o $@ $(CC_FLAGS) -c $< 
	
clean:
	rm -fr $(CODE_GEN_OBJ) $(CODE_GEN_BIN) ./test/*.o ./test/*.test

install:
	mkdir -p $(INSTALL_PATH)/http_gw
	cp $(BUILD_BIN_PATH)/../tgz/http_gw.tgz $(INSTALL_PATH)/http_gw/
	cd $(INSTALL_PATH)/http_gw&& tar xzvf http_gw.tgz

