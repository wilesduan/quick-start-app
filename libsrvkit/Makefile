include ../common.mk

INCLUDE= -I./src $(UTIL_INCLUDE) $(IM_PROTO_INCLUDE) $(PROTOBUF_INCLUDE) $(JSON_INCLUDE) $(ZOOKEEPER_INCLUDE) $(HIREDIS_VIP_INCLUDE) $(MYSQL_CONNECTOR_INCLUDE) $(NGHTTP2_INCLUDE) $(OPENSSL_INCLUDE) $(RDKAFKA_INCLUDE) $(CURL_INCLUDE)
LIBS=$(LIBSRVKIT_LIB) $(UTIL_LIB) $(JSON_LIB) $(IM_PROTO_LIB) $(PROTOBUF_LIB) $(ZOOKEEPER_LIB) $(HIREDIS_VIP_LIB) $(MYSQL_CONNECTOR_LIB) $(NGHTTP2_LIB) $(CURL_LIB) $(OPENSSL_LIB) $(RDKAFKA_LIB) $(SYS_LIB) 

LIBSRVKIT_BUILD_PATH=$(BUILD_OBJ_PATH)/libsrvkit
SOURCE=$(wildcard ./src/*.cc) 
HEADER=$(wildcard ./src/*.h) 
FILES=$(HEADER) $(SOURCE) ./src/coctx_swap.S
LIBSRVKIT_DIR=$(dir $(SOURCE))
LIBSRVKIT_SRC_OBJ=$(patsubst %.cc, $(LIBSRVKIT_BUILD_PATH)/%.o, $(SOURCE)) 
LIBSRVKIT_SRC_OBJ_DIR=$(sort $(patsubst %, $(LIBSRVKIT_BUILD_PATH)/%, $(LIBSRVKIT_DIR)))
LIBSRVKIT_S_OBJ:=$(LIBSRVKIT_BUILD_PATH)/s/coctx_swap.o
LIBSRVKIT_S_OBJ_DIR=$(LIBSRVKIT_BUILD_PATH)/s
LIBSRVKIT_OBJ=$(LIBSRVKIT_S_OBJ) $(LIBSRVKIT_SRC_OBJ)

LIBSRVKIT_LIB_DIR=$(dir $(LIBSRVKIT_LIB))
LIBSRVKIT_INCLUDE_DIR=$(GEN_SDK_PATH)/libsrvkit/include

TEST_ECHO_SRV=./test/echo_srv
TEST_ECHO_CLI=./test/echo_cli
TEST_ECHO_PRESS_CLI=./test/echo_press_cli
TEST_MID_ECHO_SRV=./test/echo_mid_srv

all:show_version libdir $(LIBSRVKIT_LIB)
	@echo "compile gentool"
	make -e $(PARA) -C gentool

show_version:
	@echo
	@echo $(VERSION_STR)
	@echo

show_echo:
	@echo $(LIBSRVKIT_S_OBJ_DIR)
	@echo $(LIBSRVKIT_OBJ)


libdir:
	mkdir -p $(LIBSRVKIT_SRC_OBJ_DIR) $(LIBSRVKIT_S_OBJ_DIR) $(LIBSRVKIT_LIB_DIR) $(LIBSRVKIT_INCLUDE_DIR)

$(LIBSRVKIT_LIB):$(LIBSRVKIT_OBJ)
	$(AR) $@ $^
	cp ./src/*.h $(LIBSRVKIT_INCLUDE_DIR)/

$(LIBSRVKIT_BUILD_PATH)/%.o : %.cc $(FILES)
	$(CXX) -o $@ $(CC_FLAGS) -c $<

$(LIBSRVKIT_S_OBJ_DIR)/coctx_swap.o : ./src/coctx_swap.S 
	$(CXX) -o $@ $(CC_FLAGS) -c $<

test_:$(TEST_ECHO_SRV) $(TEST_ECHO_CLI) $(TEST_MID_ECHO_SRV) $(TEST_ECHO_PRESS_CLI)

$(TEST_ECHO_SRV):./test/echosrv/echo_srv.o ./test/echosrv/gen_echosrv.pb.o ./test/echosrv/proto_test_srv_echosrv_imp.o ./test/echosrv/proto_test_srv_echosrv.o
	$(CXX) -o $@ $(CC_FLAGS) $^ $(LIBS)

./test/echosrv/echo_srv.o:./test/echosrv/echo_srv.c $(LIBSRVKIT_LIB) 
	$(CXX) -o $@ $(CC_FLAGS) -I ./test/echosrv -c $<

./test/echosrv/gen_echosrv.pb.o:./test/echosrv/gen_echosrv.pb.cc $(LIBSRVKIT_LIB) 
	$(CXX) -o $@ $(CC_FLAGS) -I ./test/echosrv -c $<

./test/echosrv/proto_test_srv_echosrv.o:./test/echosrv/proto_test_srv_echosrv.cc $(LIBSRVKIT_LIB) 
	$(CXX) -o $@ $(CC_FLAGS) -I ./test/echosrv -c $<

./test/echosrv/proto_test_srv_echosrv_imp.o:./test/echosrv/proto_test_srv_echosrv_imp.cc $(LIBSRVKIT_LIB) 
	$(CXX) -o $@ $(CC_FLAGS) -I ./test/echosrv -c $<

$(TEST_MID_ECHO_SRV):./test/mid_echo_srv/gen_echosrv.pb.o ./test/mid_echo_srv/proto_mid_echo_srv_mid_echo_srv.o ./test/mid_echo_srv/proto_mid_echo_srv_mid_echo_srv_imp.o ./test/mid_echo_srv/proto_test_srv_echosrv_cli.o ./test/mid_echo_srv/mid_echo_srv.o ./test/mid_echo_srv/gen_echo_mid_srv.pb.o ./test/mid_echo_srv/gen_swoole_test.pb.o ./test/mid_echo_srv/proto_test_swoole_Topic_cli.o
	$(CXX) -o $@ $(CC_FLAGS) $^ $(LIBS)

./test/mid_echo_srv/gen_swoole_test.pb.o:./test/mid_echo_srv/gen_swoole_test.pb.cc
	$(CXX) -o $@ $(CC_FLAGS) -I ./test/mid_echo_srv -c $<

./test/mid_echo_srv/proto_test_swoole_Topic_cli.o:./test/mid_echo_srv/proto_test_swoole_Topic_cli.cc
	$(CXX) -o $@ $(CC_FLAGS) -I ./test/mid_echo_srv -c $<

./test/mid_echo_srv/gen_echosrv.pb.o:./test/mid_echo_srv/gen_echosrv.pb.cc
	$(CXX) -o $@ $(CC_FLAGS) -I ./test/mid_echo_srv -c $<

./test/mid_echo_srv/proto_mid_echo_srv_mid_echo_srv.o:./test/mid_echo_srv/proto_mid_echo_srv_mid_echo_srv.cc
	$(CXX) -o $@ $(CC_FLAGS) -I ./test/mid_echo_srv -c $<

./test/mid_echo_srv/proto_mid_echo_srv_mid_echo_srv_imp.o:./test/mid_echo_srv/proto_mid_echo_srv_mid_echo_srv_imp.cc
	$(CXX) -o $@ $(CC_FLAGS) -I ./test/mid_echo_srv -c $<

./test/mid_echo_srv/proto_test_srv_echosrv_cli.o:./test/mid_echo_srv/proto_test_srv_echosrv_cli.cc
	$(CXX) -o $@ $(CC_FLAGS) -I ./test/mid_echo_srv -c $<

./test/mid_echo_srv/mid_echo_srv.o:./test/mid_echo_srv/mid_echo_srv.c
	$(CXX) -o $@ $(CC_FLAGS) -I ./test/mid_echo_srv -c $<

./test/mid_echo_srv/gen_echo_mid_srv.pb.o:./test/mid_echo_srv/gen_echo_mid_srv.pb.cc
	$(CXX) -o $@ $(CC_FLAGS) -I ./test/mid_echo_srv -c $<


$(TEST_ECHO_CLI):./test/echocli/echo_cli.o ./test/echocli/gen_echo_mid_srv.pb.o 
	$(CXX) -o $@ $(CC_FLAGS) $^ $(LIBS)

./test/echocli/echo_cli.o:./test/echocli/echo_cli.c $(LIBSRVKIT_LIB)
	$(CXX) -o $@ $(CC_FLAGS) -I ./test/echocli -c $<

./test/echocli/gen_echo_mid_srv.pb.o:./test/echocli/gen_echo_mid_srv.pb.cc $(LIBSRVKIT_LIB)
	$(CXX) -o $@ $(CC_FLAGS) -I ./test/echocli -c $<

$(TEST_ECHO_PRESS_CLI):./test/echocli/echo_press_cli.o ./test/echocli/gen_echo_mid_srv.pb.o 
	$(CXX) -o $@ $(CC_FLAGS) $^ $(LIBS)

./test/echocli/echo_press_cli.o:./test/echocli/echo_press_cli.c $(LIBSRVKIT_LIB)
	$(CXX) -o $@ $(CC_FLAGS) -I ./test/echocli -c $<



.PHONY:test
test: $(filter-out ./test/mysql_test.cc,$(TEST_SOURCE)) $(filter-out ./src/server.cc,$(SOURCE))
	$(CXX) -o $(TEST_DIR)/libsrvkit.test $(TEST_CC_FLAGS) $^ $(MOCKCPP_LIB) $(LIBS) $(SYS_LIB) $(GTEST_LIB)
	mv *.gcno $(BUILD_OBJ_PATH)

runtest:
	lcov -d $(BUILD_OBJ_PATH) -z > /dev/null 2>&1
	valgrind -q --smc-check=all $(TEST_DIR)/libsrvkit.test $(ARGS)
	$(CODECOV)

check:
	cppcheck --enable=all -j4 ./src | egrep -e "^\["

clean:
	rm -fr $(LIBSRVKIT_OBJ) $(LIBSRVKIT_LIB)  $(TEST_ECHO_CLI) $(TEST_ECHO_SRV) $(TEST_MID_ECHO_SRV) ./test/mid_echo_srv/*.o ./test/echocli/*.o ./test/echosrv/*.o $(TEST_TMPS)
	@echo "clean gentool"
	make clean -C gentool
