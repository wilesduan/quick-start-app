// Protocol Buffers - Google's data interchange format
// Copyright 2008 Google Inc.  All rights reserved.
// http://code.google.com/p/protobuf/
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Author: kenton@google.com (Kenton Varda)
//  Based on original Protocol Buffers design by
//  Sanjay Ghemawat, Jeff Dean, and others.

#ifdef _MSC_VER
#include <io.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif
#include <errno.h>
#include <iostream>
#include <algorithm>

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <concatenating_output_stream.h>
#include <google/protobuf/stubs/common.h>
#include <google/protobuf/stubs/stl_util.h>


namespace google {
namespace protobuf {
namespace io {

#ifdef _WIN32
// Win32 lseek is broken:  If invoked on a non-seekable file descriptor, its
// return value is undefined.  We re-define it to always produce an error.
#define lseek(fd, offset, origin) ((off_t)-1)
#endif

ConcatenatingOutputStream::ConcatenatingOutputStream(ZeroCopyOutputStream* const streams[], int count):streams_(streams),stream_count_(count),bytes_retired_(0)
{
}

void ConcatenatingOutputStream::Reset(ZeroCopyOutputStream* const streams[], int count)
{
	streams_ = streams;
	stream_count_ = count;
	bytes_retired_ = 0;
}

ConcatenatingOutputStream::~ConcatenatingOutputStream()
{
}

bool ConcatenatingOutputStream::Next(void** data, int* size){
  while (stream_count_ > 0) {
    if (streams_[0]->Next(data, size)) return true;

    // That stream is done.  Advance to the next one.
    bytes_retired_ += streams_[0]->ByteCount();
    ++streams_;
    --stream_count_;
  }

  // No more streams.
  return false;
}

void ConcatenatingOutputStream::BackUp(int count) {
  if (stream_count_ > 0) {
    streams_[0]->BackUp(count);
  } else {
    GOOGLE_LOG(DFATAL) << "Can't BackUp() after failed Next().";
  }
}

int64 ConcatenatingOutputStream::ByteCount() const {
  if (stream_count_ == 0) {
    return bytes_retired_;
  } else {
    return bytes_retired_ + streams_[0]->ByteCount();
  }
}
// ===================================================================
}  // namespace io
}  // namespace protobuf
}  // namespace google
