ifeq "$(DEBUG)" "no"
	PARA = -e DEBUG=no 
endif	

PACKDIR=$(DIR)

base:
	@echo "compile proto"
	make -e $(PARA) -C proto 
	@echo "compile util"
	make -e $(PARA) -C util 
	@echo "compile libsrvkit"
	make -e $(PARA) -C libsrvkit 
	@echo -e "pack libsrvkit"
	mkdir -p ./build/sdk/pack/include
	mkdir -p ./build/sdk/pack/lib
	cp ./build/obj/libsrvkit/src/* ./build/obj/libsrvkit/s/* ./build/obj/proto/src/* ./build/obj/util/src/* ./build/sdk/pack/lib/
	cd ./build/sdk/pack/lib && ar rc libsrvkit.a *.o && rm *.o && cd -
	cp ./build/sdk/libsrvkit/include/* ./build/sdk/proto/include/* ./build/sdk/util/include/* ./build/sdk/pack/include/
	@echo "compile common"
	make -e $(PARA) -C ./apps/common

http_gw:base
	@echo "compile http_gw"
	make -e $(PARA) -C ./apps/http_gw

echosrv:base
	@echo "compile echosrv"
	make -e $(PARA) -C ./apps/echosrv

all:base \
	http_gw\
	echosrv
	

clean:
	@echo "compile proto"
	make clean -C proto 
	@echo "clean util"
	make clean  -C util 
	@echo "clean libsrvkit"
	make clean -C libsrvkit 
	@echo "clean apps/common"
	make clean -C ./apps/common
	@echo "clean apps/http_gw"
	make clean -C ./apps/http_gw
	@echo "clean apps/echosrv"
	make clean -C ./apps/echosrv

install:
	@echo "install http_gw"
	make install -C ./apps/http_gw
