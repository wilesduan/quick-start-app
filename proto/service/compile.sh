#!/bin/bash  
echo $#
if [ $# -lt 1 ]
then
	echo $0 xxx.proto
	exit -1
fi

filename=$1
dir=`basename $1 .proto`

echo $filename $dir
../../build/bin/codegen -f $filename -o $dir
succ=`echo $?`
if [ $succ -ne 0 ]
then
	echo "failed to gen code"
	exit 1
fi

cp $dir/gen_proto/gen_$filename .
cp ../idl/blink.proto .
echo $dir/gen_proto/gen_$filename
./protoc --cpp_out=. gen_$filename
succ=`echo $?`
if [ $succ -ne 0 ]
then
	echo "failed to gen proto"
	exit 1
fi

cp ./gen_$dir.pb.* ../../apps/common/bo/
cp ./gen_$dir.pb.* ./$dir/gen_proto/
cp $dir/gen_cli/* ../../apps/common/stub/
rm -f ./gen_$filename ./blink.proto *.pb.h *.pb.cc
