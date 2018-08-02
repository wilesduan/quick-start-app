include ../common.mk

PROTOC=./service/protoc
INCLUDE= -I./src $(PROTOBUF_INCLUDE) 

IM_PROTO_BUILD_PATH=$(BUILD_OBJ_PATH)/proto
PROTO_FILE=$(wildcard ./idl/*.proto)

CC_SOURCE=$(patsubst ./idl/%.proto, ./src/%.pb.cc, $(PROTO_FILE))  $(wildcard ./src/*.cc)

IM_PROTO_DIR=$(dir $(CC_SOURCE))
IM_PROTO_OBJ_DIR=$(sort $(patsubst %, $(IM_PROTO_BUILD_PATH)/%, $(IM_PROTO_DIR)))
IM_PROTO_OBJ=$(patsubst %.cc, $(IM_PROTO_BUILD_PATH)/%.o, $(CC_SOURCE)) 

IM_PROTO_LIB_DIR=$(dir $(IM_PROTO_LIB))
IM_PROTO_INCLUDE_DIR=$(GEN_SDK_PATH)/proto/include


all:show_version libdir $(IM_PROTO_LIB)

show_version:
	@echo
	@echo $(VERSION_STR)
	@echo

libdir:
	mkdir -p ./src $(IM_PROTO_OBJ_DIR) $(IM_PROTO_LIB_DIR) $(IM_PROTO_INCLUDE_DIR)

$(IM_PROTO_LIB):$(IM_PROTO_OBJ)
	$(AR) $@ $^
	cp ./src/*.h $(IM_PROTO_INCLUDE_DIR)/

$(IM_PROTO_BUILD_PATH)/%.o:%.cc
	$(CXX) -o $@ $(CC_FLAGS) -c $^

./src/%.pb.cc:./idl/%.proto
	$(PROTOC) -I ./idl --cpp_out=./src/ $<

clean:
	rm -fr $(IM_PROTO_OBJ) $(IM_PROTO_LIB) $(CC_SOURCE)
