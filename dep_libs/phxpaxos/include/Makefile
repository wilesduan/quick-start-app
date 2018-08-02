SRC_BASE_PATH=/home/wilesduan/download/phxpaxos

all:lib_include 

include $(SRC_BASE_PATH)/makefile.mk

include Makefile.define
INCLUDE_SRC=$(INCLUDE_OBJ)
INCLUDE_INCS=$(sort $(SRC_BASE_PATH)/include)
INCLUDE_FULL_LIB_PATH=$(SRC_BASE_PATH)//include
INCLUDE_EXTRA_CPPFLAGS=-Wall -Werror

CPPFLAGS+=$(patsubst %,-I%, $(INCLUDE_INCS))
CPPFLAGS+=$(INCLUDE_EXTRA_CPPFLAGS)

lib_include:$(SRC_BASE_PATH)/.lib/libinclude.a

$(SRC_BASE_PATH)/.lib/libinclude.a: $(INCLUDE_SRC)
	ar -cvq $@ $(INCLUDE_SRC)

SUBDIRS=phxpaxos

.PHONY:sub_dir
sub_dir:$(SUBDIRS)
	@for sub_dir in $^; do \
	make -C $$sub_dir; \
	done

.PHONY:clean
clean:$(SUBDIRS)
	@for sub_dir in $^; do \
	make -C $$sub_dir clean;\
	done
	rm -rf *.o *.pb.* $(SRC_BASE_PATH)/.lib/libinclude.a 

