/*
 * Copyright (c) 2013 Pavel Shramov <shramov@mexmat.net>
 *
 * json2pb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef __JSON2PB_H__
#define __JSON2PB_H__

#include <string>
#include <json.h>

namespace google {
namespace protobuf {
class Message;
}
}

int util_json2pb(google::protobuf::Message* msg, const char *buf);
int util_pb2json(const google::protobuf::Message* msg, std::string& str);

int util_parse_pb_from_json(google::protobuf::Message* msg, json_object* root);
json_object* util_parse_json_from_pb(google::protobuf::Message* msg, int* array = NULL);

int util_json_object_equal(json_object* jso1, json_object* jso2);

/*
json_object* util_parse_json_from_http_params(const char* params);
int util_parse_pb_from_http_params(google::protobuf::Message* msg, const char* params);
*/

#endif//__JSON2PB_H__
