#ifndef _MY_LOG_FILE_H_
#define _MY_LOG_FILE_H_

#include "util_logger.h"

extern util_bim_logger_t* g_bim_logger;

#define LOG_DBG(format, ...)     (g_bim_logger && (LEVEL_LOG_DEBUG & g_bim_logger->log_level)) ? (util_write_log(LEVEL_LOG_DEBUG, __FILE__, __LINE__, __FUNCTION__, format, ##__VA_ARGS__ ), 0) : 0
#define LOG_ERR(format, ...)     util_write_log(LEVEL_LOG_ERROR, __FILE__, __LINE__, __FUNCTION__, format, ##__VA_ARGS__ )
#define LOG_INFO(format, ...)    (g_bim_logger && (LEVEL_LOG_INFO & g_bim_logger->log_level)) ? (util_write_log(LEVEL_LOG_INFO, __FILE__, __LINE__, __FUNCTION__, format, ##__VA_ARGS__ ), 0) : 0
#define LOG_WARN(format, ...)    (g_bim_logger && (LEVEL_LOG_WARN & g_bim_logger->log_level)) ? (util_write_log(LEVEL_LOG_WARN, __FILE__, __LINE__, __FUNCTION__, format, ##__VA_ARGS__ ), 0) : 0
#define LOG_FORCE(format, ...)   (g_bim_logger && (LEVEL_LOG_FORCE & g_bim_logger->log_level)) ? (util_write_log(LEVEL_LOG_FORCE, __FILE__, __LINE__, __FUNCTION__, format, ##__VA_ARGS__ ), 0) : 0
//上报通用统计事件
#define LOG_EVENT(event_name, content, ...)   (g_bim_logger && (LEVEL_LOG_INFO & g_bim_logger->log_level)) ? (util_write_log(LEVEL_LOG_INFO, __FILE__, __LINE__, __FUNCTION__, "ev_name:%s|" content, event_name, ##__VA_ARGS__ ), 0) : 0


#define LOG(level, ctx, prefix, args...) LOG_##level( \
        prefix", ss_trace_id=%s, uid=%llu", ##args, ctx->co->uctx.ss_trace_id_s, ctx->co->uctx.uid);

#define MONITOR_ACC(key, value) util_monitor_acc(key, value)
#define MONITOR_FINAL(key, value) util_monitor_final(key, value);
#define MONITOR_MAX(key, value) util_monitor_max(key, value);
#define MONITOR_MIN(key, value) util_monitor_min(key, value);

#endif// _MY_LOG_FILE_H_

