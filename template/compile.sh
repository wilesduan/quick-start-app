#!/bin/bash  
echo "nihao"
echo $#
if [ $# -lt 1 ]
then
	echo $0 xxx.proto
	exit -1
fi

filename=$1
dir=`basename $1 .proto`

PROJECT_HOME=
echo $filename $dir
$(PROJECT_HOME)/quick-start-app/build/bin/codegen -f $filename -o $dir
succ=`echo $?`
if [ $succ -ne 0 ]
then
	echo "failed to gen code"
	exit 1
fi

cp $dir/gen_proto/gen_$filename .
#cp ../../dep_libs/libsrvkit/include/blink.proto .
echo $dir/gen_proto/gen_$filename
$(PROJECT_HOME)/quick-start-app/proto/service/protoc --cpp_out=. gen_$filename
succ=`echo $?`
if [ $succ -ne 0 ]
then
	echo "failed to gen proto"
	exit 1
fi

cp ./gen_$dir.pb.* ../../apps/common/bo/
cp ./gen_$dir.pb.* ./$dir/gen_proto/
cp $dir/gen_cli/* ../../apps/common/stub/
rm -fr ./gen_$filename ./blink.proto *.pb.h *.pb.cc
