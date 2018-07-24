/*
 * Copyright (c) 2013 Pavel Shramov <shramov@mexmat.net>
 *
 * json2pb is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <json.h>
#include <json_object_private.h>
#include <bim_util.h>
#include <stdlib.h>

#include <google/protobuf/message.h>
#include <google/protobuf/descriptor.h>

#include <util_json2pb.h>
#include <curl.h>

namespace {
#include "util_bin2ascii.h"
}

using google::protobuf::Message;
using google::protobuf::MessageFactory;
using google::protobuf::Descriptor;
using google::protobuf::FieldDescriptor;
using google::protobuf::EnumDescriptor;
using google::protobuf::EnumValueDescriptor;
using google::protobuf::Reflection;

static json_object* _pb2json(const Message* msg, int* array = NULL);
static json_object* _field2json(const Message* msg, const FieldDescriptor *field, size_t index)
{
	const Reflection *ref = msg->GetReflection();
	const bool repeated = field->is_repeated();
	json_object*jf = 0;
	switch (field->cpp_type())
	{
#define _CONVERT(type, vtype, fmt, sfunc, afunc)		\
		case FieldDescriptor::type: {			\
			const vtype value = (repeated)?		\
				ref->afunc(*msg, field, index):	\
				ref->sfunc(*msg, field);		\
			jf = fmt(value);			\
			break;					\
		}

		_CONVERT(CPPTYPE_DOUBLE, double, json_object_new_double, GetDouble, GetRepeatedDouble);
		_CONVERT(CPPTYPE_FLOAT, double, json_object_new_double, GetFloat, GetRepeatedFloat);
		_CONVERT(CPPTYPE_INT64, int64_t, json_object_new_int64, GetInt64, GetRepeatedInt64);
		_CONVERT(CPPTYPE_UINT64, int64_t, json_object_new_int64, GetUInt64, GetRepeatedUInt64);
		_CONVERT(CPPTYPE_INT32, int32_t, json_object_new_int, GetInt32, GetRepeatedInt32);
		_CONVERT(CPPTYPE_UINT32, int32_t, json_object_new_int, GetUInt32, GetRepeatedUInt32);
		_CONVERT(CPPTYPE_BOOL, bool, json_object_new_boolean, GetBool, GetRepeatedBool);
#undef _CONVERT
		case FieldDescriptor::CPPTYPE_STRING: {
			std::string scratch;
			const std::string &value = (repeated)?
				ref->GetRepeatedStringReference(*msg, field, index, &scratch):
				ref->GetStringReference(*msg, field, &scratch);
			if (field->type() == FieldDescriptor::TYPE_BYTES){
				std::string r;
				b64_encode(value, r);
				jf = json_object_new_string(r.c_str());
			}
			else
				jf = json_object_new_string(value.c_str());
			break;
		}
		case FieldDescriptor::CPPTYPE_MESSAGE: {
			const Message& mf = (repeated)?
				ref->GetRepeatedMessage(*msg, field, index):
				ref->GetMessage(*msg, field);
			jf = _pb2json(&mf);
			break;
		}
		case FieldDescriptor::CPPTYPE_ENUM: {
			const EnumValueDescriptor* ef = (repeated)?
				ref->GetRepeatedEnum(*msg, field, index):
				ref->GetEnum(*msg, field);

			jf = json_object_new_int(ef->number());
			break;
		}
		default:
			break;
	}

	return jf;
}

static json_object* _pb2json(const Message* msg, int* array)
{
	if(array) *array = 0;
	const Descriptor *d = msg->GetDescriptor();
	const Reflection *ref = msg->GetReflection();
	if (!d || !ref) {
		LOG_ERR("null descriptor or ref");
		return NULL;
	}

	json_object*root = json_object_new_object();
	std::vector<const FieldDescriptor *> fields;
	ref->ListFields(*msg, &fields);

	for (size_t i = 0; i != fields.size(); i++)
	{
		const FieldDescriptor *field = fields[i];
		const std::string &name = (field->is_extension())?field->full_name():field->name();

		json_object* jf = NULL;
		if(field->is_repeated()) {
			jf = json_object_new_array();

			size_t count = ref->FieldSize(*msg, field);
			if (!count){
				json_object_object_add(root, name.c_str(), jf);
				continue;
			}

			for (size_t j = 0; j < count; j++){
				json_object* item = _field2json(msg, field, j);
				if(item){
					json_object_array_add(jf, item);
				}else{
					LOG_ERR("failed to convert field to json. field:%s", name.c_str());
				}
			}

			/*
			 * 为了适配私信服务中的query.room.list.do接口，
			 * 把 data 的格式改成纯数组形式。
			 * 如果是这种情况，response里只能支持一个field.
			 */
			if (name.substr(0, 2) == "__")
			{
				if(root)json_object_put(root);
				if(array) *array = 1;
				return jf;
			}
				//json_array_append_new(array.ptr, _field2json(msg, field, j));
			//jf = array.release();
		} else if (ref->HasField(*msg, field))
			jf = _field2json(msg, field, 0);
		else
			continue;

		if(jf)
			json_object_object_add(root, name.c_str(), jf);
	}

	if(!array)
		return root;

	for(int i = 0; i < d->field_count(); ++i){
		const FieldDescriptor* field = d->field(i);
		const std::string &name = (field->is_extension())?field->full_name():field->name();
		if (name.substr(0, 2) == "__"){
			*array = 1;
			break;
		}
	}

	return root;
}

static int _json2pb(Message* msg, json_object*root);
static int _json2field(Message* msg, const FieldDescriptor *field, json_object* jf)
{
	const Reflection *ref = msg->GetReflection();
	if(NULL == ref){
		LOG_ERR("no reflection in msg");
		return -1;
	}
	const bool repeated = field->is_repeated();

	switch (field->cpp_type())
	{
#define _SET_OR_ADD(sfunc, afunc, value)			\
		do {						\
			if (repeated)				\
				ref->afunc(msg, field, value);	\
			else					\
				ref->sfunc(msg, field, value);	\
		} while (0)

#define _CONVERT(type, vtype, jtype, fetcher, sfunc, afunc) 		\
		case FieldDescriptor::type: {			\
		    if(json_object_get_type(jf) != jtype){ return -1;}								\
			vtype value = fetcher(jf); \
			_SET_OR_ADD(sfunc, afunc, value);	\
			break;					\
		}

		/*
		_CONVERT(CPPTYPE_DOUBLE, double, json_type_double, json_object_get_double, SetDouble, AddDouble);
		_CONVERT(CPPTYPE_FLOAT, double, json_type_double, json_object_get_double, SetFloat, AddFloat);
		_CONVERT(CPPTYPE_INT64, int64_t, json_type_int, json_object_get_int64, SetInt64, AddInt64);
		_CONVERT(CPPTYPE_UINT64, int64_t, json_type_int, json_object_get_int64, SetUInt64, AddUInt64);
		_CONVERT(CPPTYPE_INT32, int32_t, json_type_int, json_object_get_int, SetInt32, AddInt32);
		_CONVERT(CPPTYPE_UINT32, int32_t, json_type_int, json_object_get_int, SetUInt32, AddUInt32);
		*/
		_CONVERT(CPPTYPE_BOOL, bool, json_type_boolean, json_object_get_boolean, SetBool, AddBool);
	
		case FieldDescriptor::CPPTYPE_DOUBLE:
		{
			double value = 0;
			if(json_object_get_type(jf) == json_type_string){
				const char* str = json_object_get_string(jf);
				value = strtod(str, NULL);
                _SET_OR_ADD(SetDouble, AddDouble, value);
			}else if(json_object_get_type(jf) == json_type_double){
				value = json_object_get_double(jf);
                _SET_OR_ADD(SetDouble, AddDouble, value);
			}
			break;
		}

		case FieldDescriptor::CPPTYPE_FLOAT:
		{
			float value = 0;
			if(json_object_get_type(jf) == json_type_string){
				const char* str = json_object_get_string(jf);
				value = strtof(str, NULL);
                _SET_OR_ADD(SetFloat, AddFloat, value);
			}else if(json_object_get_type(jf) == json_type_double){
				value = json_object_get_double(jf);
                _SET_OR_ADD(SetFloat, AddFloat, value);
			}
			break;
		}

		case FieldDescriptor::CPPTYPE_INT64:
		{
			int64_t value = 0;
			if(json_object_get_type(jf) == json_type_string){
				const char* str = json_object_get_string(jf);
				value = strtoll(str, NULL, 10);
                _SET_OR_ADD(SetInt64, AddInt64, value);
			}else if(json_object_get_type(jf) == json_type_int){
				value = json_object_get_int64(jf);
                _SET_OR_ADD(SetInt64, AddInt64, value);
			}
			break;
		}
		case FieldDescriptor::CPPTYPE_UINT64:
		{
			int64_t value = 0;
			if(json_object_get_type(jf) == json_type_string){
				const char* str = json_object_get_string(jf);
				value = strtoull(str, NULL, 10);
                _SET_OR_ADD(SetUInt64, AddUInt64, value);
			}else if(json_object_get_type(jf) == json_type_int){
				value = json_object_get_int64(jf);
                _SET_OR_ADD(SetUInt64, AddUInt64, value);
			}
			break;
		}
		case FieldDescriptor::CPPTYPE_INT32:
		{
			int32_t value = 0;
			if(json_object_get_type(jf) == json_type_string){
				const char* str = json_object_get_string(jf);
				value = atoi(str);
                _SET_OR_ADD(SetInt32, AddInt32, value);
			}else if(json_object_get_type(jf) == json_type_int){
				value = json_object_get_int(jf);
                _SET_OR_ADD(SetInt32, AddInt32, value);
			}
			break;
		}

		case FieldDescriptor::CPPTYPE_UINT32:
		{
			int32_t value = 0;
			if(json_object_get_type(jf) == json_type_string){
				const char* str = json_object_get_string(jf);
				value = strtoul(str, NULL, 10);
			    _SET_OR_ADD(SetUInt32, AddUInt32, value);
			}else if(json_object_get_type(jf) == json_type_int){
				value = json_object_get_int(jf);
                _SET_OR_ADD(SetUInt32, AddUInt32, value);
			}
			break;
		}

		case FieldDescriptor::CPPTYPE_STRING: {
            const char * value = NULL;
            char tmp_char[32];//64bit max length 20
			switch(json_object_get_type(jf)){
                case json_type_string:{
                    value = json_object_get_string(jf);
                    break;
                };
                case json_type_int:{
                    snprintf(tmp_char, sizeof(tmp_char), "%lld", (long long)json_object_get_int64(jf));
                    value = tmp_char;
                    break;
                };
                case json_type_double:{
                    snprintf(tmp_char, sizeof(tmp_char), "%lf", json_object_get_double(jf));
                    value = tmp_char;
                    break;
                };
                default:{
                    return -2;
                }
			}
			if(field->type() == FieldDescriptor::TYPE_BYTES){
				std::string r;
				if(b64_decode(value, r)){
					break;
				}

				_SET_OR_ADD(SetString, AddString, r);
			}else
				_SET_OR_ADD(SetString, AddString, value);
			break;
		}
		case FieldDescriptor::CPPTYPE_MESSAGE: {
			Message *mf = (repeated)?
				ref->AddMessage(msg, field):
				ref->MutableMessage(msg, field);
			if(_json2pb(mf, jf)){
				return -3;
			}
			break;
		}
		case FieldDescriptor::CPPTYPE_ENUM: {
			const EnumDescriptor *ed = field->enum_type();
			const EnumValueDescriptor *ev = 0;
			if(json_object_get_type(jf) == json_type_int){
				ev = ed->FindValueByNumber(json_object_get_int(jf));
			} else if (json_object_get_type(jf) == json_type_string) {
				ev = ed->FindValueByName(json_object_get_string(jf));
			} else{
				return -4;
			}

            if (ev == NULL)
            {
                return -4;
            }

			_SET_OR_ADD(SetEnum, AddEnum, ev);
			break;
		}
		default:
			break;
	}

	return 0;
}

static int _json_array_2_pb(Message* msg, json_object* root)
{
	const Descriptor *d = msg->GetDescriptor();
	int fc = d->field_count();
	if(fc <= 0){
		return 0;
	}

	const FieldDescriptor* field = NULL;
	for(int i = 0; i < fc; ++i){
		const FieldDescriptor* fid = d->field(i);
		if(fid->is_repeated()){
			field = fid;
			break;
		}
	}

	if(NULL == field){
		return 0;
	}

	unsigned size = json_object_array_length(root);
	for(unsigned i = 0; i < size; ++i){
		json_object* inst = json_object_array_get_idx(root, i);
		if(_json2field(msg, field, inst)){
			return -1;
		}
	}

	return 0;
}

static void _json_2_pb_array_element(json_object* obj, Message* msg)
{
	const Descriptor *d = msg->GetDescriptor();
	int fc = d->field_count();
	if(fc <= 0){
		return;
	}

	const FieldDescriptor* field = NULL;
	for(int i = 0; i < fc; ++i){
		const FieldDescriptor* fid = d->field(i);
		if(fid->is_repeated()){
			field = fid;
			break;
		}
	}

	if(NULL == field){
		return;
	}

	_json2field(msg, field, obj);
}

static int _json2pb(Message* msg, json_object* root)
{
	if(NULL == root){
		return 0;
	}

	if(json_object_get_type(root) == json_type_array){
		return _json_array_2_pb(msg, root);
	}

	const Descriptor* d = NULL;
	const Reflection* ref = NULL;
	char* key = NULL;
	json_object* val = NULL;
	lh_table* table = NULL;
	lh_entry* entry = NULL;
	const FieldDescriptor *field = NULL;
	unsigned size = 0;
	unsigned i = 0;
	json_object* inst = NULL;
	json_object* obj = NULL;
	int rc = 0;
	if(json_object_get_type(root) == json_type_string){
		const char* val_str = json_object_get_string(root);
		obj = json_tokener_parse(val_str);
		if(obj){
			root = obj;
		}
	}

	if(json_object_get_type(root) != json_type_object){
		rc = 0;
		goto end_put;
	}
	d = msg->GetDescriptor();
	ref = msg->GetReflection();
	if (!d || !ref){
		LOG_ERR("failed to get descriptor or reflection of pb");
		rc = -1;
		goto end_put;
	}

	table = json_object_get_object(root);
	if(NULL == table){
		LOG_ERR("no table in root");
		rc = -11;
		goto end_put;
	}

	entry = table->head;
	while(entry){
		key = (char*)entry->k;
		val = (json_object*)entry->v;

		if(isdigit(key[0]) && atoi(key)){
			_json_2_pb_array_element(val, msg);
			entry = entry->next;
			continue;
		}

		field = d->FindFieldByName(key);
		if(!field){
			field = ref->FindKnownExtensionByName(key);
		}

		if(!field || json_object_get_type(val) == json_type_null){
			LOG_DBG("no field or field type is null:%s", key);
			entry = entry->next;
			continue;
		}
		if (field->is_repeated()) {
			if(json_object_get_type(val) != json_type_array){
				LOG_ERR("field :%s should be array, but json type is:%d", key, json_object_get_type(val));
				rc = -3;
				goto end_put;
			}

			size = json_object_array_length(val);
			for(i = 0; i < size; ++i){
				inst = json_object_array_get_idx(val, i);
				if(_json2field(msg, field, inst)){
					rc = -4;
					goto end_put;
				}
			}

		}else{
			if(_json2field(msg, field, val)){
				rc = -5;
				goto end_put;
			}
		}

		entry = entry->next;
	}

end_put:
	if(obj){
		json_object_put(obj);
	}
	return rc;
}

int util_json2pb(Message* msg, const char *buf)
{
	json_object* root = json_tokener_parse(buf); 
	if (!root){
		LOG_ERR("failed to parse json str:%s", buf);
		return -1;
	}

	int rc = _json2pb(msg, root);
	json_object_put(root);
	return rc;
}

int util_pb2json(const google::protobuf::Message* msg, std::string& str)
{
	json_object* root = _pb2json(msg);
	if(NULL == root){
		LOG_ERR("failed to convert pb 2 json");
		return -1;
	}

	const char* p = json_object_to_json_string(root);
	str = p;
	json_object_put(root);
	return 0;
}

int util_parse_pb_from_json(google::protobuf::Message* msg, json_object* root)
{
	msg->Clear();
	return _json2pb(msg, root);
}

json_object* util_parse_json_from_pb(google::protobuf::Message* msg, int* array)
{
	return _pb2json(msg, array);
}


/*
typedef void(*fn_parse_kv)(void* arg, const char* k, const char* v);

static void enumerate_http_params(const char* params, fn_parse_kv do_parse_kv, void* arg)
{
	if(NULL == params){
		return ;
	}

	char* buff = strdup(params);
	const char* key = buff;
	const char* val = params;

	char* p = buff;
	int state = 0;
	while(*p){
		//find =
		switch(state){
			case 0:
				{
					if(*p == '='){
						*p = 0;
						val = p+1;
						state = 1;
					}
					break;
				}
		//find &
			case 1:
				{
					if(*p == '&'){
						*p = 0;
						do_parse_kv(arg, key, val);
						state = 0;
						key = p + 1;
					}

					break;
				}
			default:
				break;
		}

		++p;
	}

	if(*key && *val && key < val){
		do_parse_kv(arg, key, val);
	}

	free(buff);
	return; 
}

void do_parse_json_kv(void* arg, const char* k, const char* v)
{
	json_object* root = (json_object*)arg;
	size_t len = strlen(k);
	json_object* pf = json_object_new_string(v);
	if(len > 2 && k[len-2] == '[' && k[len-1] == ']'){
		char* buff = strndup(k, len -2);
		json_object*  array = NULL;
		json_object_object_get_ex(root, buff, &array);
		if(!array){
			array = json_object_new_array();
			json_object_object_add(root, buff, array);
		}

		json_object_array_add(array, pf);
		free(buff);
	}else{
		json_object_object_add(root, k, pf);
	}
}

json_object* util_parse_json_from_http_params(const char* params)
{
	if(NULL == params){
		return NULL;
	}
	json_object* root = json_object_new_object();
	enumerate_http_params(params, do_parse_json_kv, root);
	return root;
}

static int _str2field(Message* msg, const FieldDescriptor *field, const char* str)
{
	const Reflection *ref = msg->GetReflection();
	if(NULL == ref){
		LOG_ERR("no reflection in msg");
		return -1;
	}
	const bool repeated = field->is_repeated();

	switch (field->cpp_type())
	{
#define _STR_SET_OR_ADD(sfunc, afunc, value)			\
		do {						\
			if (repeated)				\
				ref->afunc(msg, field, value);	\
			else					\
				ref->sfunc(msg, field, value);	\
		} while (0)

	    case FieldDescriptor::CPPTYPE_BOOL:
		{
			bool value = atoi(str);
			_STR_SET_OR_ADD(SetBool, AddBool, value);
			break;
		}
	
		case FieldDescriptor::CPPTYPE_DOUBLE:
		{
			double value = strtod(str, NULL);
			_STR_SET_OR_ADD(SetDouble, AddDouble, value);
			break;
		}

		case FieldDescriptor::CPPTYPE_FLOAT:
		{
			float value = strtof(str, NULL);
			_STR_SET_OR_ADD(SetFloat, AddFloat, value);
			break;
		}

		case FieldDescriptor::CPPTYPE_INT64:
		{
			int64_t value = strtoll(str, NULL, 10);
			_STR_SET_OR_ADD(SetInt64, AddInt64, value);
			break;
		}
		case FieldDescriptor::CPPTYPE_UINT64:
		{
			int64_t value = strtoull(str, NULL, 10);
			_STR_SET_OR_ADD(SetUInt64, AddUInt64, value);
			break;
		}
		case FieldDescriptor::CPPTYPE_INT32:
		{
			int32_t value = atoi(str);
			_STR_SET_OR_ADD(SetInt32, AddInt32, value);
			break;
		}

		case FieldDescriptor::CPPTYPE_UINT32:
		{
			int32_t value =strtoul(str, NULL, 10);
			_STR_SET_OR_ADD(SetUInt32, AddUInt32, value);
			break;
		}

		case FieldDescriptor::CPPTYPE_STRING: {
			if(field->type() == FieldDescriptor::TYPE_BYTES){
				std::string r;
				if(b64_decode(str, r)){
					break;
				}

				_STR_SET_OR_ADD(SetString, AddString, r);
			}else
				_STR_SET_OR_ADD(SetString, AddString, str);
			break;
		}
		case FieldDescriptor::CPPTYPE_MESSAGE: {
			Message *mf = (repeated)?
				ref->AddMessage(msg, field):
				ref->MutableMessage(msg, field);
			char* v = curl_unescape(str, strlen(str));
			if(!v){
				LOG_ERR("failed to url decode:%s", str);
				return -3;
			}

			json_object* jf = json_tokener_parse(v);
			free(v);
			jf? _json2pb(mf, jf):0;
			if(jf){
				json_object_put(jf);
			}

			break;
		}
		case FieldDescriptor::CPPTYPE_ENUM: {
			const EnumDescriptor *ed = field->enum_type();
			const EnumValueDescriptor *ev = 0;
			if(isdigit(*str)){
				ev = ed->FindValueByNumber(atoi(str));
			} else {
				ev = ed->FindValueByName(str);
			} 

            if (ev == NULL)
            {
                return -4;
            }

			_STR_SET_OR_ADD(SetEnum, AddEnum, ev);
			break;
		}
		default:
			break;
	}

	return 0;
}

void do_parse_pb_kv(void* arg, const char* k, const char* v)
{
	google::protobuf::Message* msg = (google::protobuf::Message*)arg;
	const Descriptor* d = msg->GetDescriptor();
	const Reflection* ref = msg->GetReflection();

	const FieldDescriptor *field = NULL;
	size_t len = strlen(k);
	if(len > 2 && k[len-2] == '[' && k[len-1] == ']'){
		char* buff = strndup(k, len -2);
		field = d->FindFieldByName(buff);
		if(!field){
			field = ref->FindKnownExtensionByName(buff);
		}

		if(field && field->is_repeated()){
			_str2field(msg, field, v);
		}
		free(buff);
	}else{
		field = d->FindFieldByName(k);
		if(!field){
			field = ref->FindKnownExtensionByName(k);
		}

		if(field){
			_str2field(msg, field, v);
		}
	}
}

int util_parse_pb_from_http_params(google::protobuf::Message* msg, const char* params)
{
	enumerate_http_params(params, do_parse_pb_kv, msg);
	return 0;
}

*/

static int util_json_object_all_values_equal(json_object* jso1, json_object* jso2)
{
	struct json_object_iter iter;
	json_object *sub;

	assert(json_object_get_type(jso1) == json_type_object);
	assert(json_object_get_type(jso2) == json_type_object);
	/* Iterate over jso1 keys and see if they exist and are equal in jso2 */
        json_object_object_foreachC(jso1, iter) {
		if (!lh_table_lookup_ex(jso2->o.c_object, (void*)iter.key,
					(void**)(void *)&sub))
			return 0;
		if (!util_json_object_equal(iter.val, sub))
			return 0;
        }

	/* Iterate over jso2 keys to see if any exist that are not in jso1 */
        json_object_object_foreachC(jso2, iter) {
		if (!lh_table_lookup_ex(jso1->o.c_object, (void*)iter.key,
					(void**)(void *)&sub))
			return 0;
        }

	return 1;
}

static int util_json_array_equal(json_object* jso1, json_object* jso2)
{
	size_t len, i;

	len = json_object_array_length(jso1);
	if (len != (size_t)(json_object_array_length(jso2)))
		return 0;

	for (i = 0; i < len; i++) {
		if (!util_json_object_equal(json_object_array_get_idx(jso1, i),
				       json_object_array_get_idx(jso2, i)))
			return 0;
	}
	return 1;
}

int util_json_object_equal(json_object* jso1, json_object* jso2)
{
	if (jso1 == jso2)
		return 1;

	if (!jso1 || !jso2)
		return 0;

	if (jso1->o_type != jso2->o_type)
		return 0;

	switch(jso1->o_type) {
		case json_type_boolean:
			return (jso1->o.c_boolean == jso2->o.c_boolean);

		case json_type_double:
			return (jso1->o.c_double == jso2->o.c_double);

		case json_type_int:
			return (jso1->o.c_int64 == jso2->o.c_int64);

		case json_type_string:
			return (jso1->o.c_string.len == jso2->o.c_string.len &&
				memcmp(jso1->o.c_string.str,
				       jso2->o.c_string.str,
				       jso1->o.c_string.len) == 0);

		case json_type_object:
			return util_json_object_all_values_equal(jso1, jso2);

		case json_type_array:
			return util_json_array_equal(jso1, jso2);

		case json_type_null:
			return 1;
	};

	return 0;
}
