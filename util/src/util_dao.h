// #ifndef __BIM_UTIL_DAO__
// #define __BIM_UTIL_DAO__

#include <mysql_wrapper.h>
#include <string>
#include <vector>

// Need define macros as follows:
// 		STRUCT_NAME
//		DB_NAME
//		SUFFIX_CODE
//		NOT_USE_CACHE
//		KEY_EXPIRE_TIME
//		UPDATE_KEY	
//		SVR_NAME	
// 		S_FIELDS

// Get uid
#define GET_USERCTX_T 														\
	const userctx_t* user_ctx = get_user_ctx_from_rpc_ctx(ctx);				\
	if (NULL == user_ctx) {													\
		LOG_ERR("[%s_ALARM][__FUNCTION__]@user_ctx == NULL.", SVR_NAME);	\
		return error_code;													\
	}

// Malloc sql str
#define MALLOC_SQL_STR(t, e)																				\
    char t[40960] = ""; \
	if (NULL == t) {																						\
		return e;																							\
	}

#define GET_MYSQL_CONN(t, e, mi)																											\
	    MYSQL* t = get_mysql_from_rpc_by_id(ctx, mi);																						\
    if (ci_cb == NULL) {                                                                                                                    \
    }  else {                                                                                                                               \
	    t = get_mysql_from_rpc_by_id(ctx, ci_cb(ctx, mi).c_str());																	\
    }                                                                                                                                       \
	if(NULL == t)																															\
	{																																		\
		LOG_ERR("[_ALARM][__FUNCTION__]@get_mysql_from_rpc return NULL, uid: %llu, traceid: %llu", SVR_NAME, uid, user_ctx->ss_trace_id);	\
		return e;																															\
	}

#define MALLOC_MYSQL_QUERY(ctx, mq, mc, ss, e)																									\
	mq = mysql_malloc_query(ctx, mc, ss);																										\
	if(mq == NULL)																															\
	{																																		\
		LOG_ERR("[%s_ALARM][__FUNCTION__]@mysql_malloc_query return NULL, uid: %llu, traceid: %llu", SVR_NAME, uid, user_ctx->ss_trace_id); \
		return e;																															\
	}

// Generator table name of autoreply
#define TABLE_NAME(t, m)    												\
		char t[64] = "";													\
		if(strcmp(DB_NAME, "bim_user_notify_") == 0) {						\
			snprintf(t, sizeof(t), "%s%03lu", DB_NAME, m%SUFFIX_CODE);		\
		}																	\
        else if(strcmp(DB_NAME, "t_max_seqno_session_") == 0) {						\
			snprintf(t, sizeof(t), "%s%02lu", DB_NAME, m%SUFFIX_CODE);		\
		}																	\
		else{																\
			snprintf(t, sizeof(t), "%s%lu", DB_NAME, m%SUFFIX_CODE);		\
		}																	\
		LOG_DBG("table name: %s", t);


// Define bind
#define __BIND__(n, mf) 	mysql_bind##mf(mysql_query, &n);LOG_DBG("[bind] mf: %s, %s: %d",#mf, #n, n);
#define __BIND_STR__(n, mf) mysql_bind##mf(mysql_query, n, &n##_len);LOG_DBG("[bind_str] mf: %s, %s: %s",#mf, #n, n);

// Define result bind
#define __RESULT_BIND__(n, mf) 		mysql_result_bind##mf(mysql_query, &n, &is_##n##_null, &n##_len, &n##_error);LOG_DBG("[resut_bind] mf: %s, %s: %d",#mf, #n, n);
#define __RESULT_BIND_STR__(n, mf)  mysql_result_bind##mf(mysql_query, n, &is_##n##_null, &n##_len, &n##_error);LOG_DBG("[result_bind_str] mf: %s, %s: %s",#mf, #n, n);

// Callback of multiple read mysql
#ifndef CALLBACK_FUNC
#define CALLBACK_FUNC fn_callback
#endif
void CALLBACK_FUNC(void* buff, void* rsp);
// end Callback

typedef std::string (*CI_CB)(rpc_ctx_t*, const char*);
// Define struct template
typedef struct STRUCT_NAME {
	// Define CTX
	rpc_ctx_t* ctx;
	// ErrorCode
	int error_code;
	// Unique key for insert_on_update
	// Default NULL
	char* key;

	// The hash value of tablename
	uint64_t tb_hash_val;

	// ext select condition
	const char* ext_select;

	// on duplicate update
	char* ext_cmd;

	// index hint
	char* index_hint;

	// select num
	int num_select;

    // The get conn id callback function
    CI_CB ci_cb;

    // spec mysql id
    const char* mysql_id = "write";

// Define all field
#define __S_FIELD__(t, n, issk, mf)	\
		t n; \
		std::vector<t> n##_vec; \
		bool n##_sk; \
		my_bool is_##n##_null; \
		my_bool n##_error; \
		unsigned long n##_len;
	S_FIELDS
#undef __S_FIELD__
#define __S_FIELD__(t, n, issk, mf)	\
		t n[5000]; \
		std::vector<std::string> n##_vec; \
		bool n##_sk; \
		my_bool is_##n##_null; \
		my_bool n##_error; \
		unsigned long n##_len;
	S_FIELDS_STR
#undef __S_FIELD__

	int insert() {

		int ret = 0;
		mysql_query_t* mysql_query = NULL;

		GET_USERCTX_T;

		uint64_t uid = user_ctx->uid;

		// Get mysql connect
        LOG_DBG("mysql_id: %s", mysql_id);
		GET_MYSQL_CONN(mysql_connect, error_code, mysql_id);

		MALLOC_SQL_STR(sql_str, error_code);

		// Get DB name
#ifdef SUFFIX_CODE
		TABLE_NAME(table_name, tb_hash_val);
#else
		const char* table_name = DB_NAME;
#endif

		strcat(sql_str, "insert into ");
		strcat(sql_str, table_name);
		strcat(sql_str, "(");
// Append db fields 
#define __S_FIELD__(t, n, issk, mf)		\
			strcat(sql_str, #n);		\
			strcat(sql_str, ",");
		S_FIELDS
		S_FIELDS_STR
#undef __S_FIELD__
		// Remove Last ,
		sql_str[strlen(sql_str) - 1] = ')';

		strcat(sql_str, " values(");
#define __S_FIELD__(t, n, issk, mf)		\
			strcat(sql_str, "?,");
		S_FIELDS
		S_FIELDS_STR
#undef __S_FIELD__
		sql_str[strlen(sql_str) - 1] = ')';

		if(NULL != ext_cmd)
		{
			strcat(sql_str, " ");
			strcat(sql_str, ext_cmd);
		}
		LOG_DBG("[%s_ALARM][insert]sql_str: %s", SVR_NAME, sql_str);

		MALLOC_MYSQL_QUERY(ctx, mysql_query, mysql_connect, sql_str, error_code);

#define __S_FIELD__(t, n, issk, mf) __BIND__(n, mf)
		S_FIELDS
#undef __S_FIELD__
#define __S_FIELD__(t, n, issk, mf) __BIND_STR__(n, mf)
		S_FIELDS_STR
#undef __S_FIELD__
	
		if(execute_mysql_query(mysql_query))
		{
			LOG_ERR("[%s_ALARM][insert]@failed to execute query: %s", SVR_NAME, mysql_query->reslt.mysql_errmsg);
			ret = error_code;
		}

		if (mysql_query) mysql_free_query(mysql_query);
#ifdef NOT_USE_CACHE
		return ret;
#else
		return ret?ret:update_cache();
#endif
	}

	int update()
	{
		int ret = 0;
		mysql_query_t* mysql_query = NULL;

		GET_USERCTX_T;

		uint64_t uid = user_ctx->uid;

		// Get mysql connect
        LOG_DBG("mysql_id: %s", mysql_id);
		GET_MYSQL_CONN(mysql_connect, error_code, mysql_id);

		MALLOC_SQL_STR(sql_str, error_code);

		// Get DB name
#ifdef SUFFIX_CODE
		TABLE_NAME(table_name, tb_hash_val);
#else
		const char* table_name = DB_NAME;
#endif

		strcat(sql_str, "update ");
		strcat(sql_str, table_name);
		strcat(sql_str, " set ");
// Append db fields 
#define __S_FIELD__(t, n, issk, mf)		\
			strcat(sql_str, #n);	\
			strcat(sql_str, "=?,");
		S_FIELDS
		S_FIELDS_STR
#undef __S_FIELD__
		// Remove Last ,
		sql_str[strlen(sql_str) - 1] = ' ';

		strcat(sql_str, " where 1=1 ");

#ifdef UPDATE_KEY
#define __UPDATE_KEY__(n, mf)			\
			strcat(sql_str, " and ");	\
			strcat(sql_str, #n);		\
			strcat(sql_str, " = ? ");
		UPDATE_KEY
#undef __UPDATE_KEY__
#endif

#ifdef UPDATE_STR_KEY
#define __UPDATE_KEY__(n, mf)			\
			strcat(sql_str, " and ");	\
			strcat(sql_str, #n);		\
			strcat(sql_str, " = ? ");
		UPDATE_STR_KEY
#undef __UPDATE_KEY__
#endif

		if (NULL != ext_select)
		{
			strcat(sql_str, " ");
			strcat(sql_str, ext_select);
		}

		LOG_DBG("[update]sql_str: %s", sql_str);

		MALLOC_MYSQL_QUERY(ctx, mysql_query, mysql_connect, sql_str, error_code);

#define __S_FIELD__(t, n, issk, mf) __BIND__(n, mf)
		S_FIELDS
#undef __S_FIELD__
#define __S_FIELD__(t, n, issk, mf) __BIND_STR__(n, mf)
		S_FIELDS_STR
#undef __S_FIELD__

#ifdef UPDATE_KEY
#define __UPDATE_KEY__(n, mf)	\
			__BIND__(n, mf)
			UPDATE_KEY
#undef __UPDATE_KEY__
#endif

#ifdef UPDATE_STR_KEY
#define __UPDATE_KEY__(n, mf)	\
			__BIND_STR__(n, mf)
			UPDATE_STR_KEY
#undef __UPDATE_KEY__
#endif
	
		if(execute_mysql_query(mysql_query))
		{
			LOG_ERR("[%s_ALARM][update]@failed to execute query: %s", SVR_NAME, mysql_query->reslt.mysql_errmsg);
			ret = error_code;
		}

		if (mysql_query) mysql_free_query(mysql_query);
#ifdef NOT_USE_CACHE
		return ret;
#else
		return ret?ret:update_cache();
#endif
	}

	int update_cache()
	{
		GET_USERCTX_T;

		// Delete old cache
		call_redis(ctx, "DEL %s%llu", DB_NAME, user_ctx->uid);

		// Insert New Cache
		char buf[256] = "";
		strcat(buf, "HMSET %s%llu ");

#define __S_FIELD__(t, n, issk, mf)		\
			strcat(buf, #n); strcat(buf, " %ld ");
		S_FIELDS
#undef __S_FIELD__
#define __S_FIELD__(t, n, issk, mf)		\
			strcat(buf, #n); strcat(buf, " %s ");
		S_FIELDS_STR
#undef __S_FIELD__
		
		LOG_DBG("[%s_ALARM][update_cache]buf: %s", SVR_NAME, buf);

		call_redis(ctx, buf, DB_NAME, user_ctx->uid
#define __S_FIELD__(t, n, issk, mf) , n
		S_FIELDS
		S_FIELDS_STR
#undef __S_FIELD__
		);

		// Reset key expire time
		char expire_buf[128] = "";
		strcat(expire_buf, "EXPIRE %s%llu %llu");
		call_redis(ctx, expire_buf, DB_NAME, user_ctx->uid, KEY_EXPIRE_TIME);
		return 0;
	}

	int read()
	{
		// return _read_from_cache()??!??!_read_from_db()?0:error_code;
#ifdef NOT_USE_CACHE
		return _read_from_db()?0:error_code;
#else
		return (_read_from_cache()||_read_from_db())?0:error_code;
#endif
	}

	bool _read_from_db()
	{
		int ret = 0;
		mysql_query_t* mysql_query = NULL;

		GET_USERCTX_T;

		uint64_t uid = user_ctx->uid;

		// Get mysql connect
        LOG_DBG("mysql_id: %s", mysql_id);
		GET_MYSQL_CONN(mysql_connect, error_code, mysql_id);

		MALLOC_SQL_STR(sql_str, error_code);

		// Get DB name
#ifdef SUFFIX_CODE
		TABLE_NAME(table_name, tb_hash_val);
#else
		const char* table_name = DB_NAME;
#endif

		strcat(sql_str, "select ");
// Append db fields 
#define __S_FIELD__(t, n, issk, mf)		\
			strcat(sql_str, #n);	\
			strcat(sql_str, ",");
		S_FIELDS
		S_FIELDS_STR
#undef __S_FIELD__
		// Remove Last ,
		sql_str[strlen(sql_str) - 1] = ' ';

		strcat(sql_str, " from ");
		strcat(sql_str, table_name);
		if(NULL != index_hint)
		{
			strcat(sql_str, " ");
			strcat(sql_str, index_hint);
		}
		strcat(sql_str, " where 1=1 ");
#define __S_FIELD__(t, n, issk, mf)			\
			if (issk) {						\
				strcat(sql_str, " and ");	\
				strcat(sql_str, #n);		\
				strcat(sql_str, " = ? ");	\
			}
		S_FIELDS
		S_FIELDS_STR
#undef __S_FIELD__

		if (NULL != ext_select)
		{
			strcat(sql_str, " ");
			strcat(sql_str, ext_select);
		}

		LOG_DBG("Read: sql_str: %s", sql_str);

		MALLOC_MYSQL_QUERY(ctx, mysql_query, mysql_connect, sql_str, error_code);

#define __S_FIELD__(t, n, issk, mf) if (issk) {__BIND__(n, mf);}
		S_FIELDS
#undef __S_FIELD__
#define __S_FIELD__(t, n, issk, mf) if (issk) {__BIND_STR__(n, mf);}
		S_FIELDS_STR
#undef __S_FIELD__

#define __S_FIELD__(t, n, issk, mf) __RESULT_BIND__(n, mf)
		S_FIELDS
#undef __S_FIELD__
#define __S_FIELD__(t, n, issk, mf) __RESULT_BIND_STR__(n, mf)
		S_FIELDS_STR
#undef __S_FIELD__

		if(execute_mysql_query(mysql_query))
		{
			LOG_ERR("[%s_ALARM][_read_from_db]@failed to execute query: %s, sql: %s", SVR_NAME, mysql_query->reslt.mysql_errmsg, sql_str);
			ret = error_code;
		}
		else
		{
			int num = mysql_enumerate_rslt(mysql_query, CALLBACK_FUNC, this, NULL);
			LOG_DBG("query num: %d", num);
		}

		if (mysql_query) mysql_free_query(mysql_query);

#ifndef NOT_USE_CACHE
		if (ret == 0) {
			return update_cache() == 0;
		}
		return false;
#endif

		return ret == 0;
		// return (ret?ret:update_cache()) == 0;
	}
	bool _read_from_cache()
	{
		GET_USERCTX_T;

		// Define get value of each key macro
#ifndef __HGET_KEY__
#define __HGET_KEY__(k)																		\
		reply = call_redis(ctx, "HGET %s%llu %s", DB_NAME, tb_hash_val, #k);				\
		if (reply != NULL && reply->type == REDIS_REPLY_INTEGER) 							\
		{																					\
			this->k = reply->integer;														\
		} 																					\
		else if (reply != NULL && reply->type == REDIS_REPLY_STRING) 						\
		{																					\
			this->k = std::stoull(std::string(reply->str));									\
		} 																					\
		else                                                                                \
		{                                                                                   \
			LOG_ERR("[_read_from_cache] read cache error: %s\n", #k);						\
			return false;																	\
		}
#endif

#ifndef __HGET_STR_KEY__
#define __HGET_STR_KEY__(k)																	\
		reply = call_redis(ctx, "HGET %s%llu %s", DB_NAME, tb_hash_val, #k);				\
		if (reply != NULL && reply->type == REDIS_REPLY_STRING) 							\
		{                                                                                   \
			strncpy(this->k, reply->str, reply->len);                                     	\
			this->k##_len = reply->len;                                                   	\
		}                                                                                   \
		else                                                                                \
		{                                                                                   \
			LOG_ERR("[_read_from_cache2] read cache error: %s\n", #k);						\
			return false;																	\
		}
#endif

		redisReply* reply = NULL; 
#define __S_FIELD__(t, n, issk, mf) __HGET_KEY__(n);
		S_FIELDS
#undef __S_FIELD__
#define __S_FIELD__(t, n, issk, mf) __HGET_STR_KEY__(n);
		S_FIELDS_STR
#undef __S_FIELD__

#undef __HGET_KEY__
#undef __HGET_STR_KEY__
	
		// LOG_DBG("[_read_from_cache] read cache sucess\n");
		return true;
	}

	int clear()
	{
		int ret = 0;
		mysql_query_t* mysql_query = NULL;

		GET_USERCTX_T;

		uint64_t uid = user_ctx->uid;

		// Get mysql connect
        LOG_DBG("mysql_id: %s", mysql_id);
		GET_MYSQL_CONN(mysql_connect, error_code, mysql_id);

		MALLOC_SQL_STR(sql_str, error_code);

		// Get DB name
#ifdef SUFFIX_CODE
		TABLE_NAME(table_name, tb_hash_val);
#else
		const char* table_name = DB_NAME;
#endif

		strcat(sql_str, "delete from ");
		strcat(sql_str, table_name);
		strcat(sql_str, " where 1=1 ");
#define __S_FIELD__(t, n, issk, mf)			\
			if (issk) {						\
				strcat(sql_str, " and ");	\
				strcat(sql_str, #n);		\
				strcat(sql_str, " = ? ");	\
			}
		S_FIELDS
		S_FIELDS_STR
#undef __S_FIELD__

		LOG_DBG("[%s_ALARM][clear]sql_str: %s", SVR_NAME, sql_str);

#define __S_FIELD__(t, n, issk, mf) if (issk) {__BIND__(n, mf)}
		S_FIELDS
#undef __S_FIELD__
#define __S_FIELD__(t, n, issk, mf) if (issk) {__BIND_STR__(n, mf)}
		S_FIELDS_STR
#undef __S_FIELD__
	
		MALLOC_MYSQL_QUERY(ctx, mysql_query, mysql_connect, sql_str, error_code);

		LOG_DBG("readt to execute_mysql_query");
		if(execute_mysql_query(mysql_query))
		{
			LOG_ERR("[%s_ALARM][clear]@failed to execute query: %s", SVR_NAME, mysql_query->reslt.mysql_errmsg);
			ret = error_code;
		}

		if (mysql_query) mysql_free_query(mysql_query);
#ifdef NOT_USE_CACHE
		return ret;
#else
		return ret?ret:clear_cache();
#endif
	}
	
	int clear_cache()
	{
		GET_USERCTX_T;

		// Delete old cache
		call_redis(ctx, "DEL %s%llu", DB_NAME, user_ctx->uid);

		return 0;
	}

	STRUCT_NAME() {
			ctx = NULL;
			// key = UPDATE_KEY;	
			error_code = 0;
			tb_hash_val = 0;
			ext_select = NULL;
			ext_cmd = NULL;
			index_hint = NULL;
			num_select = 0;
            ci_cb = NULL;

#define __S_FIELD__(t, n, issk, mf)	\
			n##_sk = issk; /* Indicate is or not select key */ \
			n##_len = 0; \
			n = 0;
		S_FIELDS
#undef __S_FIELD__

#define __S_FIELD__(t, n, issk, mf)	\
			n##_sk = issk; /* Indicate is or not select key */ \
			n##_len = 5000; \
            memset(n, 0, 5000);
		S_FIELDS_STR
#undef __S_FIELD__
	}
	~STRUCT_NAME() {
	}

} STRUCT_NAME; 

// Callback of multiple read mysql
void CALLBACK_FUNC(void* buff, void* rsp)
{
	STRUCT_NAME* ptr = (STRUCT_NAME*)buff;

#define __S_FIELD__(t, n, issk, mf)	\
		ptr->n##_vec.push_back(ptr->n);
	S_FIELDS
#undef __S_FIELD__
#define __S_FIELD__(t, n, issk, mf)	\
        if (ptr->is_##n##_null) \
		    ptr->n##_vec.push_back(std::string("")); \
        else \
		    ptr->n##_vec.push_back(std::string(ptr->n, ptr->n##_len));
	S_FIELDS_STR
#undef __S_FIELD__

	++(ptr->num_select);

}

// end Callback
#undef GET_USERCTX_T
#undef MALLOC_SQL_STR
#undef GET_MYSQL_CONN
#undef TABLE_NAME
#undef MALLOC_MYSQL_QUERY

// #endif
