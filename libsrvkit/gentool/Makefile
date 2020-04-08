include ../../common.mk

INCLUDE= -I./ 
LIBS=

CODE_GEN_BUILD_PATH=$(BUILD_OBJ_PATH)/libsrvkit/gentool
SOURCE=$(wildcard ./*.cc) $(wildcard ./*.c) 
CODE_GEN_DIR=$(dir $(SOURCE))
CODE_GEN_OBJ_DIR=$(sort $(patsubst %, $(CODE_GEN_BUILD_PATH)/%, $(CODE_GEN_DIR)))
CODE_GEN_OBJ=$(patsubst %.c, $(CODE_GEN_BUILD_PATH)/%.o, $(SOURCE)) 
CODE_GEN_BIN=$(BUILD_BIN_PATH)/codegen

LEX=flex
YACC=yacc

all:show_version dir y.tab.c y.tab.h lex.yy.c  $(CODE_GEN_BIN)

show_version:
	@echo
	@echo $(VERSION_STR)
	@echo


dir:
	echo $(CODE_GEN_OBJ)
	mkdir -p $(CODE_GEN_OBJ_DIR) $(BUILD_BIN_PATH)

y.tab.c y.tab.h:mysql_query.y
	$(YACC) -d mysql_query.y

lex.yy.c:mysql_query.l
	$(LEX) mysql_query.l

$(CODE_GEN_BIN):$(CODE_GEN_OBJ)
	$(CXX) -o $@ $^

$(CODE_GEN_BUILD_PATH)/%.o : %.c ./proto.h file_gen.h file_parser.h
	$(CXX) -o $@ $(CC_FLAGS) -c $<

clean:
	rm -fr $(CODE_GEN_OBJ) $(CODE_GEN_BIN) 
