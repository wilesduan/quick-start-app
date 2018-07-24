#include <gtest/gtest.h>
#include "util_logger.cc"
#include <mockcpp/mockcpp.hpp>

#include <string>
using namespace std;

TEST(ut_logger, check_logging_2_elk)
{
    g_bim_logger = (util_bim_logger_t*)calloc(1, sizeof(util_bim_logger_t));
    g_bim_logger->log_level = LEVEL_LOG_ANY;
    g_bim_logger->unix_sock_alarm_fd = 1;

    // case 1: ALARM
    ASSERT_TRUE(check_logging_2_elk(LEVEL_LOG_ERROR, "[x_ALARM]xxxxxxxxxxxx"));

    // case 2: NOTICE
    ASSERT_TRUE(check_logging_2_elk(LEVEL_LOG_INFO, "#BLINK_NOTICE#xxxxxxxxxxx"));

    // case 3: filter
    ASSERT_FALSE(check_logging_2_elk(LEVEL_LOG_INFO, "#BLINKxNOTICE#xxxxxxxxxxx"));

    // case 4: filter
    ASSERT_FALSE(check_logging_2_elk(LEVEL_LOG_ERROR, "[x_ALARMxxxxxxxxxxxx"));
}

TEST(ut_logger, DISABLED_util_write_log)
{
    g_bim_logger = (util_bim_logger_t*)calloc(1, sizeof(util_bim_logger_t));
    g_bim_logger->log_level = LEVEL_LOG_ANY;
    g_bim_logger->unix_sock_alarm_fd = 1;
    g_bim_logger->local_path = strdup("1111");
    g_bim_logger->remote_udp_fd = 1;

    // case 1: need_log:true need_log_2_elk:true
    MOCKER(check_logging_2_elk)
        .expects(once())
        .will(returnValue(true));
    MOCKER(send_alarm_to_elk)
        .expects(once());
    util_write_log(LEVEL_LOG_ERROR, "test", 0, "func", "111111");
    GlobalMockObject::verify();

    // case 2: need_log:true need_log_2_elk:false
    MOCKER(check_logging_2_elk)
        .expects(once())
        .will(returnValue(false));
    MOCKER(send_alarm_to_elk)
        .expects(never());
    util_write_log(LEVEL_LOG_ERROR, "test", 0, "func", "111111");
    GlobalMockObject::verify();

    // case 3: need_log:false need_log_2_elk:true
    g_bim_logger->log_level = 0;
    MOCKER(check_logging_2_elk)
        .expects(once())
        .will(returnValue(true));
    MOCKER(send_alarm_to_elk)
        .expects(once());
    util_write_log(LEVEL_LOG_ERROR, "test", 0, "func", "111111");
    GlobalMockObject::verify();

    // case 4: need_log:false need_log_2_elk:false
    g_bim_logger->log_level = 0;
    MOCKER(check_logging_2_elk)
        .expects(once())
        .will(returnValue(false));
    MOCKER(send_alarm_to_elk)
        .expects(never());
    util_write_log(LEVEL_LOG_ERROR, "test", 0, "func", "111111");
    GlobalMockObject::verify();
}

TEST(ut_logger, open_unix_socket)
{
    g_bim_logger = (util_bim_logger_t*)calloc(1, sizeof(util_bim_logger_t));

    // case 1: ALARM
    MOCKER(gen_unix_sockaddr)
        .stubs()
        .will(returnValue(0));

    MOCKER(socket)
        .stubs()
        .will(returnValue(1));

    MOCKER(util_fcntl)
        .expects(once())
        .will(returnValue(0));

    ASSERT_EQ(open_unix_socket(), 0);

    GlobalMockObject::verify();

    // case 2: NOTICE
    MOCKER(gen_unix_sockaddr)
        .stubs()
        .will(returnValue(0));

    MOCKER(socket)
        .stubs()
        .will(returnValue(1))
        .then(repeat(1, 2))
        .then(returnValue(0));

    MOCKER(util_fcntl)
        .expects(once());

    ASSERT_EQ(open_unix_socket(), 0);

    GlobalMockObject::verify();
}

bool checkHostName(char* host_name)
{
    strcpy(host_name, "test");
    return true;
}

char sz_log[0x10000] = {0};
bool checkLog(const struct iovec* v)
{
    sz_log[0] = 0;
    strncat(sz_log, (const char*)v[0].iov_base, v[0].iov_len);
    strncat(sz_log, (const char*)v[1].iov_base, v[1].iov_len);
    return true;
}

TEST(ut_logger, util_send_to_elk)
{
    g_bim_logger->appname = strdup("appname");

    // case 1: check access major args
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        json_object* jso = json_object_new_object();
        util_send_to_elk(LEVEL_LOG_INFO, "access", jso);
        if(jso) json_object_put(jso);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        ts /= 1000;
        char sz_buffer[0x100] = {0};
        strftime(sz_buffer, sizeof(sz_buffer) - 1, "%FT%TZ", gmtime((time_t*)&ts));

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* time = NULL;
        json_object_object_get_ex(root, "time", &time);
        const char* str = json_object_get_string(time);
        ASSERT_EQ(strcmp(str, sz_buffer), 0);

        json_object* level = NULL;
        json_object_object_get_ex(root, "level", &level);
        str = json_object_get_string(level);
        ASSERT_EQ(strcmp(str, "INFO"), 0);

        json_object* app_id = NULL;
        json_object_object_get_ex(root, "app_id", &app_id);
        str = json_object_get_string(app_id);
        ASSERT_EQ(strcmp(str, "bplus-access-appname"), 0);

        json_object* instance_id = NULL;
        json_object_object_get_ex(root, "instance_id", &instance_id);
        str = json_object_get_string(instance_id);
        ASSERT_EQ(strcmp(str, "test"), 0);

        if(root) json_object_put(root);
    }

    // case 2: check alarm major args
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        json_object* jso = json_object_new_object();
        util_send_to_elk(LEVEL_LOG_ERROR, "alarm", jso);
        if(jso) json_object_put(jso);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        ts /= 1000;
        char sz_buffer[0x100] = {0};
        strftime(sz_buffer, sizeof(sz_buffer) - 1, "%FT%TZ", gmtime((time_t*)&ts));

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* time = NULL;
        json_object_object_get_ex(root, "time", &time);
        const char* str = json_object_get_string(time);
        ASSERT_EQ(strcmp(str, sz_buffer), 0);

        json_object* level = NULL;
        json_object_object_get_ex(root, "level", &level);
        str = json_object_get_string(level);
        ASSERT_EQ(strcmp(str, "ERROR"), 0);

        json_object* app_id = NULL;
        json_object_object_get_ex(root, "app_id", &app_id);
        str = json_object_get_string(app_id);
        ASSERT_EQ(strcmp(str, "bplus-alarm-appname"), 0);

        json_object* instance_id = NULL;
        json_object_object_get_ex(root, "instance_id", &instance_id);
        str = json_object_get_string(instance_id);
        ASSERT_EQ(strcmp(str, "test"), 0);

        if(root) json_object_put(root);
    }

    // case 3: check rpc major args
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        json_object* jso = json_object_new_object();
        util_send_to_elk(LEVEL_LOG_INFO, "rpc", jso);
        if(jso) json_object_put(jso);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        ts /= 1000;
        char sz_buffer[0x100] = {0};
        strftime(sz_buffer, sizeof(sz_buffer) - 1, "%FT%TZ", gmtime((time_t*)&ts));

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* time = NULL;
        json_object_object_get_ex(root, "time", &time);
        const char* str = json_object_get_string(time);
        ASSERT_EQ(strcmp(str, sz_buffer), 0);

        json_object* level = NULL;
        json_object_object_get_ex(root, "level", &level);
        str = json_object_get_string(level);
        ASSERT_EQ(strcmp(str, "INFO"), 0);

        json_object* app_id = NULL;
        json_object_object_get_ex(root, "app_id", &app_id);
        str = json_object_get_string(app_id);
        ASSERT_EQ(strcmp(str, "bplus-rpc-appname"), 0);

        json_object* instance_id = NULL;
        json_object_object_get_ex(root, "instance_id", &instance_id);
        str = json_object_get_string(instance_id);
        ASSERT_EQ(strcmp(str, "test"), 0);

        if(root) json_object_put(root);
    }

    // case 4: instance_id => UNKNOWN
    {
        MOCKER(gethostname)
            .stubs()
            .will(returnValue(1));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        json_object* jso = json_object_new_object();
        util_send_to_elk(LEVEL_LOG_INFO, "access", jso);
        if(jso) json_object_put(jso);

        GlobalMockObject::verify();

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* instance_id = NULL;
        json_object_object_get_ex(root, "instance_id", &instance_id);
        const char* str = json_object_get_string(instance_id);
        ASSERT_EQ(strcmp(str, "UNKNOWN"), 0);

        if(root) json_object_put(root);
    }
}

TEST(ut_logger, send_alarm_to_elk_alarm_format)
{
    g_bim_logger->appname = strdup("appname");

    // case 1: check alarm format 1
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        char sz_log_test[0x100] = "1:1048576:2018-01-08 18:04:20:./src/util.cc:100:func_test|[xxx_ALARM][yyy]@call xxx::yyy failed. rc:1024, trace_id:12234abc, uid:1542";
        send_alarm_to_elk(LEVEL_LOG_ERROR, sz_log_test);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* code = NULL;
        json_object_object_get_ex(root, "code", &code);
        ASSERT_EQ(json_object_get_int64(code), 1024);

        json_object* trace_id = NULL;
        json_object_object_get_ex(root, "trace_id", &trace_id);
        const char* str = json_object_get_string(trace_id);
        ASSERT_EQ(strcmp(str, "12234abc"), 0);

        json_object* uid = NULL;
        json_object_object_get_ex(root, "uid", &uid);
        ASSERT_EQ(json_object_get_int64(uid), 1542);

        json_object* module = NULL;
        json_object_object_get_ex(root, "module", &module);
        str = json_object_get_string(module);
        ASSERT_EQ(strcmp(str, "xxx"), 0);

        json_object* alarm_type = NULL;
        json_object_object_get_ex(root, "alarm_type", &alarm_type);
        str = json_object_get_string(alarm_type);
        ASSERT_EQ(strcmp(str, "yyy"), 0);

        json_object* details = NULL;
        json_object_object_get_ex(root, "details", &details);
        str = json_object_get_string(details);
        ASSERT_EQ(strcmp(str, "call xxx::yyy failed. rc:1024, trace_id:12234abc, uid:1542"), 0);

        if(root) json_object_put(root);
    }

    // case 2: check alarm format 2
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        char sz_log_test[0x100] = "1:1048576:2018-01-08 18:04:20:./src/util.cc:100:func_test|[xxx_ALARM][yyy]@return code:1044, trace_id:12234abc, uid:1542";
        send_alarm_to_elk(LEVEL_LOG_ERROR, sz_log_test);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* code = NULL;
        json_object_object_get_ex(root, "code", &code);
        ASSERT_EQ(json_object_get_int64(code), 1044);

        json_object* trace_id = NULL;
        json_object_object_get_ex(root, "trace_id", &trace_id);
        const char* str = json_object_get_string(trace_id);
        ASSERT_EQ(strcmp(str, "12234abc"), 0);

        json_object* uid = NULL;
        json_object_object_get_ex(root, "uid", &uid);
        ASSERT_EQ(json_object_get_int64(uid), 1542);

        json_object* module = NULL;
        json_object_object_get_ex(root, "module", &module);
        str = json_object_get_string(module);
        ASSERT_EQ(strcmp(str, "xxx"), 0);

        json_object* alarm_type = NULL;
        json_object_object_get_ex(root, "alarm_type", &alarm_type);
        str = json_object_get_string(alarm_type);
        ASSERT_EQ(strcmp(str, "yyy"), 0);

        json_object* details = NULL;
        json_object_object_get_ex(root, "details", &details);
        str = json_object_get_string(details);
        ASSERT_EQ(strcmp(str, "return code:1044, trace_id:12234abc, uid:1542"), 0);

        if(root) json_object_put(root);
    }

    // case 3: check alarm format 3
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        char sz_log_test[0x100] = "1:1048576:2018-01-08 18:04:20:./src/util.cc:100:func_test|[xxx_ALARM][yyy]@failed to parse reponse of type:test from json, trace_id:12234abc, uid:1542";
        send_alarm_to_elk(LEVEL_LOG_ERROR, sz_log_test);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* code = NULL;
        json_object_object_get_ex(root, "code", &code);
        ASSERT_TRUE(!code);

        json_object* trace_id = NULL;
        json_object_object_get_ex(root, "trace_id", &trace_id);
        const char* str = json_object_get_string(trace_id);
        ASSERT_EQ(strcmp(str, "12234abc"), 0);

        json_object* uid = NULL;
        json_object_object_get_ex(root, "uid", &uid);
        ASSERT_EQ(json_object_get_int64(uid), 1542);

        json_object* module = NULL;
        json_object_object_get_ex(root, "module", &module);
        str = json_object_get_string(module);
        ASSERT_EQ(strcmp(str, "xxx"), 0);

        json_object* alarm_type = NULL;
        json_object_object_get_ex(root, "alarm_type", &alarm_type);
        str = json_object_get_string(alarm_type);
        ASSERT_EQ(strcmp(str, "yyy"), 0);

        json_object* details = NULL;
        json_object_object_get_ex(root, "details", &details);
        str = json_object_get_string(details);
        ASSERT_EQ(strcmp(str, "failed to parse reponse of type:test from json, trace_id:12234abc, uid:1542"), 0);

        if(root) json_object_put(root);
    }

    // case 4: check alarm format 4
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        char sz_log_test[0x100] = "1:1048576:2018-01-08 18:04:20:./src/util.cc:100:func_test|[xxx_ALARM][yyy]@failed to parse request req, trace_id:12234abc, uid:1542";
        send_alarm_to_elk(LEVEL_LOG_ERROR, sz_log_test);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* code = NULL;
        json_object_object_get_ex(root, "code", &code);
        ASSERT_TRUE(!code);

        json_object* trace_id = NULL;
        json_object_object_get_ex(root, "trace_id", &trace_id);
        const char* str = json_object_get_string(trace_id);
        ASSERT_EQ(strcmp(str, "12234abc"), 0);

        json_object* uid = NULL;
        json_object_object_get_ex(root, "uid", &uid);
        ASSERT_EQ(json_object_get_int64(uid), 1542);

        json_object* module = NULL;
        json_object_object_get_ex(root, "module", &module);
        str = json_object_get_string(module);
        ASSERT_EQ(strcmp(str, "xxx"), 0);

        json_object* alarm_type = NULL;
        json_object_object_get_ex(root, "alarm_type", &alarm_type);
        str = json_object_get_string(alarm_type);
        ASSERT_EQ(strcmp(str, "yyy"), 0);

        json_object* details = NULL;
        json_object_object_get_ex(root, "details", &details);
        str = json_object_get_string(details);
        ASSERT_EQ(strcmp(str, "failed to parse request req, trace_id:12234abc, uid:1542"), 0);

        if(root) json_object_put(root);
    }

    // case 5: check alarm format 5
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        char sz_log_test[0x100] = "1:1048576:2018-01-08 18:04:20:./src/util.cc:100:func_test|[xxx_ALARM][yyy]@failed to alloc mem for service:test";
        send_alarm_to_elk(LEVEL_LOG_ERROR, sz_log_test);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* module = NULL;
        json_object_object_get_ex(root, "module", &module);
        const char* str = json_object_get_string(module);
        ASSERT_EQ(strcmp(str, "xxx"), 0);

        json_object* alarm_type = NULL;
        json_object_object_get_ex(root, "alarm_type", &alarm_type);
        str = json_object_get_string(alarm_type);
        ASSERT_EQ(strcmp(str, "yyy"), 0);

        json_object* code = NULL;
        json_object_object_get_ex(root, "code", &code);
        ASSERT_TRUE(!code);

        json_object* trace_id = NULL;
        json_object_object_get_ex(root, "trace_id", &trace_id);
        ASSERT_TRUE(!trace_id);

        json_object* uid = NULL;
        json_object_object_get_ex(root, "uid", &uid);
        ASSERT_TRUE(!uid);

        json_object* details = NULL;
        json_object_object_get_ex(root, "details", &details);
        str = json_object_get_string(details);
        ASSERT_EQ(strcmp(str, "failed to alloc mem for service:test"), 0);

        if(root) json_object_put(root);
    }

    // case 6: check UNKNOWN alarm format
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        char sz_log_test[0x100] = "11111";
        send_alarm_to_elk(LEVEL_LOG_ERROR, sz_log_test);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* log = NULL;
        json_object_object_get_ex(root, "log", &log);
        const char* str = json_object_get_string(log);
        ASSERT_EQ(strcmp(str, "11111"), 0);

        json_object* alarm_type = NULL;
        json_object_object_get_ex(root, "alarm_type", &alarm_type);
        ASSERT_TRUE(!alarm_type);

        json_object* code = NULL;
        json_object_object_get_ex(root, "code", &code);
        ASSERT_TRUE(!code);

        json_object* trace_id = NULL;
        json_object_object_get_ex(root, "trace_id", &trace_id);
        ASSERT_TRUE(!trace_id);

        json_object* uid = NULL;
        json_object_object_get_ex(root, "uid", &uid);
        ASSERT_TRUE(!uid);

        json_object* module = NULL;
        json_object_object_get_ex(root, "module", &module);
        ASSERT_TRUE(!module);

        json_object* details = NULL;
        json_object_object_get_ex(root, "details", &details);
        ASSERT_TRUE(!details);

        if(root) json_object_put(root);
    }

    // case 7: check alarm format - uid length limitation
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        char sz_log_test[0x100] = "1:1048576:2018-01-08 18:04:20:./src/util.cc:100:func_test|[xxx_ALARM][yyy]@call xxx::yyy failed. rc:1024, trace_id:12234abc, uid:18446744073709551615";
        send_alarm_to_elk(LEVEL_LOG_ERROR, sz_log_test);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* uid = NULL;
        json_object_object_get_ex(root, "uid", &uid);
        ASSERT_EQ(json_object_get_int64(uid), 1844674407370955161);

        json_object* details = NULL;
        json_object_object_get_ex(root, "details", &details);
        const char* str = json_object_get_string(details);
        ASSERT_EQ(strcmp(str, "call xxx::yyy failed. rc:1024, trace_id:12234abc, uid:18446744073709551615"), 0);

        if(root) json_object_put(root);
    }

    // case 8: check alarm format - code length limitation
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        char sz_log_test[0x100] = "1:1048576:2018-01-08 18:04:20:./src/util.cc:100:func_test|[xxx_ALARM][yyy]@call xxx::yyy failed. rc:2147483647, trace_id:12234abc, uid:1542";
        send_alarm_to_elk(LEVEL_LOG_ERROR, sz_log_test);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* code = NULL;
        json_object_object_get_ex(root, "code", &code);
        ASSERT_EQ(json_object_get_int64(code), 214748364);

        json_object* details = NULL;
        json_object_object_get_ex(root, "details", &details);
        const char* str = json_object_get_string(details);
        ASSERT_EQ(strcmp(str, "call xxx::yyy failed. rc:2147483647, trace_id:12234abc, uid:1542"), 0);

        if(root) json_object_put(root);
    }

    // case 9: check alarm format - code length limitation
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        char sz_log_test[0x100] = "1:1048576:2018-01-08 18:04:20:./src/util.cc:100:func_test|[xxx_ALARM][yyy]@return code:2147483647, trace_id:12234abc, uid:1542";
        send_alarm_to_elk(LEVEL_LOG_ERROR, sz_log_test);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* code = NULL;
        json_object_object_get_ex(root, "code", &code);
        ASSERT_EQ(json_object_get_int64(code), 214748364);

        json_object* details = NULL;
        json_object_object_get_ex(root, "details", &details);
        const char* str = json_object_get_string(details);
        ASSERT_EQ(strcmp(str, "return code:2147483647, trace_id:12234abc, uid:1542"), 0);

        if(root) json_object_put(root);
    }

    // case 10: check alarm format - trace_id length limitation
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        char sz_log_test[0x1000] = "1:1048576:2018-01-08 18:04:20:./src/util.cc:100:func_test|[xxx_ALARM][yyy]@return code:2147483647, trace_id:12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678, uid:1542";
        send_alarm_to_elk(LEVEL_LOG_ERROR, sz_log_test);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* trace_id = NULL;
        json_object_object_get_ex(root, "trace_id", &trace_id);
        const char* str = json_object_get_string(trace_id);
        ASSERT_EQ(strcmp(str, "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567"), 0);

        json_object* details = NULL;
        json_object_object_get_ex(root, "details", &details);
        str = json_object_get_string(details);
        ASSERT_EQ(strcmp(str, "return code:2147483647, trace_id:12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678, uid:1542"), 0);

        if(root) json_object_put(root);
    }
}

TEST(ut_logger, send_alarm_to_elk_access_format)
{
    g_bim_logger->appname = strdup("appname");

    // case 1: check access format 1
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        char sz_log_test[0x100] = "#BLINK_NOTICE#[xxx@yyy|12234abc|500ms|1024|1542|0|0][ {\"test\":[0]} ][{\"test\":[0]}]";
        send_alarm_to_elk(LEVEL_LOG_INFO, sz_log_test);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* code = NULL;
        json_object_object_get_ex(root, "code", &code);
        ASSERT_EQ(json_object_get_int64(code), 1024);

        json_object* cost = NULL;
        json_object_object_get_ex(root, "cost", &cost);
        ASSERT_EQ(json_object_get_int64(cost), 500);

        json_object* trace_id = NULL;
        json_object_object_get_ex(root, "trace_id", &trace_id);
        const char* str = json_object_get_string(trace_id);
        ASSERT_EQ(strcmp(str, "12234abc"), 0);

        json_object* uid = NULL;
        json_object_object_get_ex(root, "uid", &uid);
        ASSERT_EQ(json_object_get_int64(uid), 1542);

        json_object* cmd = NULL;
        json_object_object_get_ex(root, "cmd", &cmd);
        str = json_object_get_string(cmd);
        ASSERT_EQ(strcmp(str, "xxx.yyy"), 0);

        json_object* params = NULL;
        json_object_object_get_ex(root, "params", &params);
        str = json_object_get_string(params);
        ASSERT_EQ(strcmp(str, "[ {\"test\":[0]} ][{\"test\":[0]}]"), 0);

        if(root) json_object_put(root);
    }

    // case 2: check access format 2
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        char sz_log_test[0x100] = "#BLINK_NOTICE#[xxx@yyy|12234abc|500ms|1024|1542|0|0][ { \"test\": [ 0 ] } ]";
        send_alarm_to_elk(LEVEL_LOG_INFO, sz_log_test);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* code = NULL;
        json_object_object_get_ex(root, "code", &code);
        ASSERT_EQ(json_object_get_int64(code), 1024);

        json_object* cost = NULL;
        json_object_object_get_ex(root, "cost", &cost);
        ASSERT_EQ(json_object_get_int64(cost), 500);

        json_object* trace_id = NULL;
        json_object_object_get_ex(root, "trace_id", &trace_id);
        const char* str = json_object_get_string(trace_id);
        ASSERT_EQ(strcmp(str, "12234abc"), 0);

        json_object* uid = NULL;
        json_object_object_get_ex(root, "uid", &uid);
        ASSERT_EQ(json_object_get_int64(uid), 1542);

        json_object* cmd = NULL;
        json_object_object_get_ex(root, "cmd", &cmd);
        str = json_object_get_string(cmd);
        ASSERT_EQ(strcmp(str, "xxx.yyy"), 0);

        json_object* params = NULL;
        json_object_object_get_ex(root, "params", &params);
        str = json_object_get_string(params);
        ASSERT_EQ(strcmp(str, "[ { \"test\": [ 0 ] } ]"), 0);

        if(root) json_object_put(root);
    }

    // case 3: check UNKNOWN access format
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        char sz_log_test[0x100] = "11111";
        send_alarm_to_elk(LEVEL_LOG_INFO, sz_log_test);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* code = NULL;
        json_object_object_get_ex(root, "code", &code);
        ASSERT_TRUE(!code);

        json_object* cost = NULL;
        json_object_object_get_ex(root, "cost", &cost);
        ASSERT_TRUE(!cost);

        json_object* log = NULL;
        json_object_object_get_ex(root, "log", &log);
        const char* str = json_object_get_string(log);
        ASSERT_EQ(strcmp(str, "11111"), 0);

        json_object* uid = NULL;
        json_object_object_get_ex(root, "uid", &uid);
        ASSERT_TRUE(!uid);

        json_object* cmd = NULL;
        json_object_object_get_ex(root, "cmd", &cmd);
        ASSERT_TRUE(!cmd);

        json_object* params = NULL;
        json_object_object_get_ex(root, "params", &params);
        ASSERT_TRUE(!params);

        if(root) json_object_put(root);
    }

    // case 4: check access format - cost length limitation
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        char sz_log_test[0x100] = "#BLINK_NOTICE#[xxx@yyy|12234abc|4294967295ms|1024|1542|0|0][ {\"test\":[0]} ][{\"test\":[0]}]";
        send_alarm_to_elk(LEVEL_LOG_INFO, sz_log_test);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* cost = NULL;
        json_object_object_get_ex(root, "cost", &cost);
        ASSERT_EQ(json_object_get_int64(cost), 429496729);

        if(root) json_object_put(root);
    }

    // case 5: check access format - code length limitation
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        char sz_log_test[0x100] = "#BLINK_NOTICE#[xxx@yyy|12234abc|500ms|4294967295|1542|0|0][ {\"test\":[0]} ][{\"test\":[0]}]";
        send_alarm_to_elk(LEVEL_LOG_INFO, sz_log_test);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* code = NULL;
        json_object_object_get_ex(root, "code", &code);
        ASSERT_EQ(json_object_get_int64(code), 429496729);

        if(root) json_object_put(root);
    }

    // case 6: check access format - uid length limitation
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        char sz_log_test[0x100] = "#BLINK_NOTICE#[xxx@yyy|12234abc|500ms|1024|18446744073709551615|0|0][ {\"test\":[0]} ][{\"test\":[0]}]";
        send_alarm_to_elk(LEVEL_LOG_INFO, sz_log_test);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* uid = NULL;
        json_object_object_get_ex(root, "uid", &uid);
        ASSERT_EQ(json_object_get_int64(uid), 1844674407370955161);

        if(root) json_object_put(root);
    }

    // case 7: check access format - trace_id length limitation
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        char sz_log_test[0x1000] = "#BLINK_NOTICE#[xxx@yyy|12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678|500ms|1024|18446744073709551615|0|0][ {\"test\":[0]} ][{\"test\":[0]}]";
        send_alarm_to_elk(LEVEL_LOG_ERROR, sz_log_test);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        json_object* root = json_tokener_parse(sz_log + 19);

        json_object* cost = NULL;
        json_object_object_get_ex(root, "cost", &cost);
        ASSERT_TRUE(!cost);

        if(root) json_object_put(root);
    }
}


TEST(ut_logger, send_alarm_to_elk_params_too_long)
{
    g_bim_logger->appname = strdup("appname");

    // case 1: check alarm format 1
    {
        MOCKER(gethostname)
            .stubs()
            .with(checkWith(checkHostName), any())
            .will(returnValue(0));
        MOCKER(connect)
            .stubs()
            .will(returnValue(0));
        MOCKER(writev)
            .stubs()
            .with(any(), checkWith(checkLog))
            .will(returnValue(0));

        struct timeval now;
        gettimeofday(&now, NULL);
        char sz_log_test[4096] = "2:11652:2018-03-14 10:41:03:src/proto_dynamic_dynamic_svr.cc:310:fn_swoole_dynamic_svr_space_history|#BLINK_NOTICE#[dynamic_svr@space_history|23ceb8c1901c46b:219dcd5df4ad46b:|14ms|0|162417|0|0][{ \"visitor_uid\": 162417, \"host_uid\": 673816, \"offset_dynamic_id\": 0 }][{ \"cards\": [ { \"desc\": { \"uid\": 673816, \"type\": 8, \"rid\": 20607077, \"acl\": 0, \"view\": 0, \"repost\": 4, \"like\": 795, \"is_liked\": 0, \"dynamic_id\": 93823852639268070, \"timestamp\": 1520683468, \"pre_dy_id\": 0, \"orig_dy_id\": 0, \"orig_type\": 0, \"user_profile\": { \"info\": { \"uid\": 673816, \"uname\": \"谜之声\", \"face\": \"http:\\/\\/i0.hdslb.com\\/bfs\\/face\\/72cbf1464b28fc0d3d361529a1e2071c7fa7452c.jpg\" }, \"card\": { \"official_verify\": { \"type\": -1, \"desc\": \"\" } } }, \"stype\": 0, \"r_type\": 1, \"inner_id\": 0 }, \"card\": \"{ \\\"aid\\\": 20607077, \\\"videos\\\": 2, \\\"tid\\\": 17, \\\"tname\\\": \\\"单机联机\\\", \\\"copyright\\\": 1, \\\"pic\\\": \\\"http:\\\\\\/\\\\\\/i2.hdslb.com\\\\\\/bfs\\\\\\/archive\\\\\\/61c09f619e9cd9a6063db02461c12a943dcc20c5.jpg\\\", \\\"title\\\": \\\"【谜之声实况】有人做了个奇妙探险队的洞穴探险Mod（￣▽￣）\\\\\\/\\\", \\\"pubdate\\\": 1520683466, \\\"ctime\\\": 1520683467, \\\"desc\\\": \\\"相关游戏: 奇妙探险队\\\\n简介补充: 前几天直播晕3D的时候，有不少人表示有粉丝做了个探险队的洞穴探险mod，于是就播了一次。作者做得非常用心，妹子秃子店老板卡里神黄金城地狱阎王一应俱全，还有不少梗。然后玩的时候运气也不错，第一次就地狱通关了，相当开心，所以也把这一局剪辑一下发上来啦。\\\\n\\\\n因为探险队本身节奏比较慢的缘故，视频比较长，就不多做删减了！mod作者在直播后也更新了几次修正了不少bug，有兴趣的也可以去下来玩玩看~\\\\n\\\\nmod页在这里：https:\\\\\\/\\\\\\/steamcommunity.com\\\\\\/shared\\\", \\\"state\\\": 0, \\\"attribute\\\": 16512, \\\"duration\\\": 8906, \\\"rights\\\": { \\\"bp\\\": 0, \\\"elec\\\": 0, \\\"download\\\": 0, \\\"movie\\\": 0, \\\"pay\\\": 0, \\\"hd5\\\": 0, \\\"no_reprint\\\": 1 }, \\\"owner\\\": { \\\"mid\\\": 673816, \\\"name\\\": \\\"谜之声\\\", \\\"face\\\": \\\"http:\\\\\\/\\\\\\/i2.hdslb.com\\\\\\/bfs\\\\\\/face\\\\\\/72cbf1464b28fc0d3d361529a1e2071c7fa7452c.jpg\\\" }, \\\"stat\\\": { \\\"aid\\\": 20607077, \\\"view\\\": 43572, \\\"danmaku\\\": 1119, \\\"reply\\\": 286, \\\"favorite\\\": 434, \\\"coin\\\": 1370, \\\"share\\\": 27, \\\"now_rank\\\": 0, \\\"his_rank\\\": 0, \\\"like\\\": 795 }, \\\"dynamic\\\": \\\"相关游戏: 奇妙探险队\\\\n简介补充: 前几天直播晕3D的时候，有不少人表示有粉丝做了个探险队的洞穴探险mod，于是就播了一次。作者做得非常用心，妹子秃子店老板卡里神黄金城地狱阎王一应俱全，还有不少梗。然后玩的时候运气也不错，第一次就地狱通关了，相当开心，所以也把这一局剪辑一下发上来啦。\\\\n\\\\n因为探险队本身节奏比较慢的缘故，视频比较长，就不多做删减了！mod作者在直播后也更新了几次修正了不少bug，有兴趣的也可以去下来玩玩看~\\\\n\\\\nmod页在这里：https:\\\\\\/\\\\\\/ste\\\" }\" }, { \"desc\": { \"uid\": 673816, \"type\": 8, \"rid\": 20556509, \"acl\": 0, \"view\": 0, \"repost\": 6, \"like\": 1128, \"is_liked\": 0, \"dynamic_id\": 93427710627655608, \"timestamp\": 1520591234, \"pre_dy_id\": 0, \"orig_dy_id\": 0, \"orig_type\": 0, \"user_profile\": { \"info\": { \"uid\": 673816, \"uname\": \"谜之声\", \"face\": \"http:\\/\\/i0.hdslb.com\\/bfs\\/face\\/72cbf1464b28fc0d3d361529a1e2071c7fa7452c.jpg\" }, \"card\": { \"official_verify\": { \"type\": -1, \"desc\": \"\" } } }, \"stype\": 0, \"r_type\": 1, \"inner_id\": 0 }, \"card\": \"{ \\\"aid\\\": 20556509, \\\"videos\\\": 2, \\\"tid\\\": 17, \\\"tname\\\": \\\"单机联机\\\", \\\"copyright\\\": 1, \\\"pic\\\": \\\"http:\\\\\\/\\\\\\/i0.hdslb.com\\\\\\/bfs\\\\\\/archive\\\\\\/28e5dcebec3639193216d4a97152e4af6ef78d8d.jpg\\\", \\\"title\\\": \\\"【谜之声实况】想吃樱桃的脸黑先生 CHUCHEL\\\", \\\"pubdate\\\": 1520591231, \\\"ctime\\\": 1520591233, \\\"desc\\\": \\\"相关游戏: CHUCHEL\\\\n简介补充: 昨晚直播的《机械迷城》制作组的新作，不过这作基本没有什么解谜成分，可以看成是个看片游戏，每一“关”其实更像是动画片的一集，围绕主角小黑球和小老鼠抢樱桃的主";
        send_alarm_to_elk(LEVEL_LOG_INFO, sz_log_test);

        GlobalMockObject::verify();

        ASSERT_EQ(strncmp(sz_log, "000161", 6), 0);

        long long ts = atoll(sz_log + 6);
        ASSERT_TRUE(now.tv_sec * 1000 + now.tv_usec / 1000 - ts <= 1000);

        json_object* root = json_tokener_parse(sz_log + 19);

        printf("%s\n", sz_log + 19);

        json_object* params = NULL;
        json_object_object_get_ex(root, "params", &params);
        const char* str = json_object_get_string(params);
        printf("%s\n", str);

        if(root) json_object_put(root);
    }
}
