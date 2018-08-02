include ../../common.mk

INCLUDE= -I. -I./bo -I./stub $(ALL_INCLUDES)


BO_GEN_BUILD_PATH=$(BUILD_OBJ_PATH)/apps/common/bo
BO_SOURCE=$(wildcard ./bo/*.cc) 
BO_CODE_GEN_DIR=$(dir $(BO_SOURCE))
BO_CODE_GEN_OBJ_DIR=$(sort $(patsubst %, $(BO_GEN_BUILD_PATH)/%, $(BO_CODE_GEN_DIR)))
APP_BO_LIB_OBJ=$(patsubst %.cc, $(BO_GEN_BUILD_PATH)/%.o, $(BO_SOURCE))

STUB_GEN_BUILD_PATH=$(BUILD_OBJ_PATH)/apps/common/stub
STUB_SOURCE=$(wildcard ./stub/*.cc)
STUB_CODE_GEN_DIR=$(dir $(STUB_SOURCE))
STUB_CODE_GEN_OBJ_DIR=$(sort $(patsubst %, $(STUB_GEN_BUILD_PATH)/%, $(STUB_CODE_GEN_DIR)))
APP_STUB_LIB_OBJ=$(patsubst %.cc, $(STUB_GEN_BUILD_PATH)/%.o, $(STUB_SOURCE))

APP_BO_LIB_DIR=$(dir $(APP_BO_LIB))
APP_BO_LIB_INCLUDE_DIR=$(APP_BO_LIB_DIR)/../include

APP_STUB_LIB_DIR=$(dir $(APP_STUB_LIB))
APP_STUB_LIB_INCLUDE_DIR=$(APP_STUB_LIB_DIR)/../include

all:show_version lib_bo_dir lib_stub_dir $(APP_BO_LIB) $(APP_STUB_LIB)

lib_bo_dir:
	mkdir -p $(BO_CODE_GEN_OBJ_DIR) $(APP_BO_LIB_DIR) $(APP_BO_LIB_INCLUDE_DIR)

lib_stub_dir:
	mkdir -p $(STUB_CODE_GEN_OBJ_DIR) $(APP_STUB_LIB_DIR) $(APP_STUB_LIB_INCLUDE_DIR)

show_version:
	@echo
	@echo $(VERSION_STR)
	@echo

$(APP_BO_LIB):$(APP_BO_LIB_OBJ)
	$(AR) $@ $^
	cp ./bo/*.h $(APP_BO_LIB_INCLUDE_DIR)

$(BO_GEN_BUILD_PATH)/%.o : %.cc
	$(CXX) -o $@ $(CC_FLAGS) -c $<

$(STUB_GEN_BUILD_PATH)/%.o : %.cc
	$(CXX) -o $@ $(CC_FLAGS) -c $<

$(APP_STUB_LIB):$(APP_STUB_LIB_OBJ)
	$(AR) $@ $^
	cp ./stub/*.h $(APP_STUB_LIB_INCLUDE_DIR)

clean:
	rm -f $(APP_BO_LIB_OBJ) $(APP_STUB_LIB_OBJ) $(APP_STUB_LIB) $(APP_BO_LIB)
	echo "clean common"
