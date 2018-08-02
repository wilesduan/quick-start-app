INCLUDE($ENV{CMAKE}/common/prep.cmake)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(proto)

SET(TARGET_TYPE ARCHIVE)

SET(NEED_PROTOBUF TRUE)

SET(SDK_LIB_NAME proto)

FILE(GLOB PROTO_FILES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ./idl/*.proto)
MESSAGE(STATUS "converting proto files....")
FOREACH(proto_file ${PROTO_FILES})
    GET_FILENAME_COMPONENT(proto_file_we ${proto_file} NAME_WE)
    # 跟踪proto文件是否生成,若已生成不会再次编译
    IF(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/src/${proto_file_we}.pb.cc)
        # MESSAGE(STATUS "converting ${proto_file} success...")
    ELSE()
        EXECUTE_PROCESS(COMMAND ./protoc -I ./idl --cpp_out=./src/ ${proto_file}
                            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                            RESULT_VARIABLE pro_rval ERROR_VARIABLE error_rvar
                        )
        IF(NOT ${pro_rval} EQUAL 0)
            # for Debug
            MESSAGE("")
            MESSAGE("fatal_error:${error_rvar}")
            MESSAGE(FATAL_ERROR "(LINE:${CMAKE_CURRENT_LIST_LINE}) ${proto_file} failed")
        ENDIF()
    ENDIF()
    LIST(APPEND CLEAN_PROTO_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/${proto_file_we}.pb.cc)
ENDFOREACH()
MESSAGE(STATUS "converting proto files SUCCESS")

INCLUDE($ENV{CMAKE}/common/target.cmake)
