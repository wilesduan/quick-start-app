PROJECT_HOME=
DEP_LIBS_HOME=$(PROJECT_HOME)/quick-start-app/dep_libs

JSON_INCLUDE:=-I$(DEP_LIBS_HOME)/json/include/json-c
JSON_LIB:=$(DEP_LIBS_HOME)/json/lib/libjson-c.a

PROTOBUF_INCLUDE:=-I$(DEP_LIBS_HOME)/protobuf/include
PROTOBUF_LIB:=$(DEP_LIBS_HOME)/protobuf/lib/libprotobuf.a 

OPENSSL_INCLUDE:=-I$(DEP_LIBS_HOME)/openssl/include
OPENSSL_LIB:=$(DEP_LIBS_HOME)/openssl/lib/libssl.a $(DEP_LIBS_HOME)/openssl/lib/libcrypto.a 

ZOOKEEPER_INCLUDE:=-I$(DEP_LIBS_HOME)/zookeeper/include
ZOOKEEPER_LIB:=$(DEP_LIBS_HOME)/zookeeper/lib/libzkmt.a $(DEP_LIBS_HOME)/zookeeper/lib/libhashtable.a

HIREDIS_VIP_INCLUDE:=-I$(DEP_LIBS_HOME)/hiredis-vip/include
HIREDIS_VIP_LIB:=$(DEP_LIBS_HOME)/hiredis-vip/lib/libhiredis_vip.a

MYSQL_CONNECTOR_INCLUDE:=-I$(DEP_LIBS_HOME)/mysql/include
MYSQL_CONNECTOR_LIB:=$(DEP_LIBS_HOME)/mysql/lib/libmysqlclient.a

PHXPAXOS_INCLUDE:=-I$(DEP_LIBS_HOME)/phxpaxos/include
PHXPAXOS_LIB:=$(DEP_LIBS_HOME)/phxpaxos/lib/libphxpaxos.a

LEVELDB_INCLUDE:=-I$(DEP_LIBS_HOME)/leveldb/include
LEVELDB_LIB:=$(DEP_LIBS_HOME)/leveldb/lib/libleveldb.a

RDKAFKA_INCLUDE:=-I$(DEP_LIBS_HOME)/librdkafka/include
RDKAFKA_LIB:=$(DEP_LIBS_HOME)/librdkafka/lib/librdkafka.a

TCMALLOC_LIB:=$(DEP_LIBS_HOME)/tcmalloc/libtcmalloc.a

NGHTTP2_INCLUDE:=-I$(DEP_LIBS_HOME)/nghttp2/include
NGHTTP2_LIB:=$(DEP_LIBS_HOME)/nghttp2/lib/libnghttp2.a

CURL_INCLUDE:=-I$(DEP_LIBS_HOME)/curl/include
CURL_LIB:=$(DEP_LIBS_HOME)/curl/lib/libcurl.a

GTEST_INCLUDE:=-I$(DEP_LIBS_HOME)/gtest/include
GTEST_LIB:= -Wl,-rpath=$(DEP_LIBS_HOME)/gtest/lib -L$(DEP_LIBS_HOME)/gtest/lib -lgtest -lpthread -lgtest_main

MOCKCPP_INCLUDE:=-I$(DEP_LIBS_HOME)/mockcpp/include
MOCKCPP_LIB:=$(DEP_LIBS_HOME)/mockcpp/lib/libmockcpp.a

#####################end dependent libraries#################################

BUILD_PATH=$(PROJECT_HOME)/build
BUILD_OBJ_PATH=$(BUILD_PATH)/obj
BUILD_BIN_PATH=$(BUILD_PATH)/bin
GEN_SDK_PATH=$(BUILD_PATH)/sdk

QUICK_START_INCLUDE:=-I$(PROJECT_HOME)/quick-start-app/build/sdk/pack/include $(JSON_INCLUDE)
QUICK_START_LIB:=$(PROJECT_HOME)/quick-start-app/build/sdk/pack/lib/libsrvkit.a $(JSON_LIB)

APP_BO_INCLUDE:=-I$(GEN_SDK_PATH)/apps/common/bo/include
APP_BO_LIB:=$(GEN_SDK_PATH)/apps/common/bo/lib/libcommbo.a

APP_STUB_INCLUDE:=-I$(GEN_SDK_PATH)/apps/common/stub/include
APP_STUB_LIB:=$(GEN_SDK_PATH)/apps/common/stub/lib/libcommstub.a

ALL_INCLUDES:=$(CURL_INCLUDE) $(JSON_INCLUDE) $(PROTOBUF_INCLUDE) $(OPENSSL_INCLUDE) $(ZOOKEEPER_INCLUDE) $(HIREDIS_VIP_INCLUDE) $(MYSQL_CONNECTOR_INCLUDE) $(QUICK_START_INCLUDE) $(APP_BO_INCLUDE) $(APP_STUB_INCLUDE) $(NGHTTP2_INCLUDE) $(RDKAFKA_INCLUDE) -I$(PROJECT_HOME)/apps/common
SYS_LIB:=-lrt -lpthread -ldl
ALL_LIBS:=$(APP_BO_LIB) $(APP_STUB_LIB) $(QUICK_START_LIB) $(CURL_LIB) $(JSON_LIB) $(PROTOBUF_LIB) $(OPENSSL_LIB) $(ZOOKEEPER_LIB) $(HIREDIS_VIP_LIB) $(MYSQL_CONNECTOR_LIB) $(NGHTTP2_LIB) $(RDKAFKA_LIB) $(SYS_LIB) $(TCMALLOC_LIB) 


AR=ar rc
CXX=g++

ifeq "DEBUG" "no"
	 VERSION_STR:=---This is a RELEASE version--- 
	 CC_FLAGS = -fPIC -D_POSIX_MT_ -Wall -D_GLIBCXX_USE_CXX11_ABI=0 $(INCLUDE)
else
	 VERSION_STR:=++++++This is a Debug version++++
	 CC_FLAGS = -fPIC -D_POSIX_MT_ -g -Wall -D_GLIBCXX_USE_CXX11_ABI=0 $(INCLUDE)
endif

export GCOV_PREFIX=$(BUILD_OBJ_PATH)
TEST_SOURCE=$(wildcard ./test/*.cc)
TEST_DIR=./test
TEST_CC_FLAGS=-fPIC -D_POSIX_MT_ -Wall -D_GLIBCXX_USE_CXX11_ABI=0 -pthread -g -O0 -fprofile-arcs -ftest-coverage -fprofile-dir=. $(MOCKCPP_INCLUDE) $(GTEST_INCLUDE) $(INCLUDE)
TEST_TMPS=$(TEST_DIR)/*.test $(BUILD_OBJ_PATH)/*.gcno $(BUILD_OBJ_PATH)/*.gcda $(BUILD_OBJ_PATH)/cov.info ./coverage_report
CODECOV=lcov -b . -d $(BUILD_OBJ_PATH) -c -o $(BUILD_OBJ_PATH)/cov.info  > /dev/null 2>&1 && lcov -q -r $(BUILD_OBJ_PATH)/cov.info '/usr/*' 'test/*' '*/dep_libs/*' -o $(BUILD_OBJ_PATH)/cov.info && lcov -q -l $(BUILD_OBJ_PATH)/cov.info && genhtml -q -o ./coverage_report $(BUILD_OBJ_PATH)/cov.info

ifeq ($(PACK_PREV), 1)
	CFG_POSTFIX = .pre
endif

ifeq ($(PACK_TEST), 1)
	CFG_POSTFIX = .test
else 
ifeq ($(PACK_PREV), 1)
	CFG_POSTFIX = .pre
else
	CFG_POSTFIX = .online
endif

endif


INSTALL_PATH = /data/app/
