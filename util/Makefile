include ../common.mk

INCLUDE=$(PROTOBUF_INCLUDE) $(OPENSSL_INCLUDE) $(JSON_INCLUDE) $(CURL_INCLUDE) $(APP_BO_INCLUDE) -I./src 
LIBS=$(PROTOBUF_LIB) $(CURL_LIB) $(OPENSSL_LIB) $(JSON_LIB) 

UTIL_BUILD_PATH=$(BUILD_OBJ_PATH)/util
SOURCE=$(wildcard ./src/*.cc)
UTIL_DIR=$(dir $(SOURCE))
UTIL_OBJ_DIR=$(sort $(patsubst %, $(UTIL_BUILD_PATH)/%, $(UTIL_DIR)))
UTIL_OBJ=$(patsubst %.cc, $(UTIL_BUILD_PATH)/%.o, $(SOURCE))
UTIL_INCLUDE_DIR=$(dir $(UTIL_INCLUDE))
UTIL_LIB=$(GEN_SDK_PATH)/util/lib/libutil.a
UTIL_LIB_DIR=$(dir $(UTIL_LIB))

all:show_version libdir $(UTIL_LIB)

show_version:
	@echo
	@echo $(VERSION_STR)
	@echo


libdir:
	echo $(UTIL_BUILD_PATH)
	mkdir -p $(UTIL_OBJ_DIR) $(UTIL_LIB_DIR) $(GEN_SDK_PATH)/util/include

$(UTIL_LIB):$(UTIL_OBJ)
	$(AR) $@ $^
	cp src/*.h $(GEN_SDK_PATH)/util/include

$(UTIL_BUILD_PATH)/%.o:%.cc %.h
	$(CXX) -o $@ $(CC_FLAGS) -c $<

.PHONY:test
test: $(TEST_SOURCE) $(filter-out ./src/util_logger.cc,$(SOURCE))
	$(CXX) -o $(TEST_DIR)/util.test $(TEST_CC_FLAGS) $^ $(MOCKCPP_LIB) $(LIBS) $(SYS_LIB) $(GTEST_LIB)

runtest:
	mkdir -p ./coverage
	lcov --directory ./coverage --zerocounters > /dev/null 2>&1 
	valgrind -q --smc-check=all $(TEST_DIR)/util.test $(ARGS)

codecov:
	lcov --directory . --capture --output-file ./coverage/coverage.info > /dev/null 2>&1 # capture coverage info
	lcov --remove ./coverage/coverage.info '/usr/*' 'test/*' '*/dep_libs/*' --output-file ./coverage/coverage.info > /dev/null 2>&1 # filter out system
	lcov --list ./coverage/coverage.info #debug info
	genhtml -o ./coverage/report ./coverage/coverage.info > /dev/null 2>&1 

check:
	cppcheck --enable=all -j4 ./src | egrep -e "^\["

clean:
	rm -fr $(UTIL_OBJ) $(UTIL_LIB) $(TEST_DIR)/*.o $(TEST_DIR)/*.test *.gcno *.gcda ./coverage
