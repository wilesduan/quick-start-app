#include <gtest/gtest.h>
#include "../src/zk.cc"
#include <mockcpp/mockcpp.hpp>

#include <list>
#include <string>
using namespace std;

TEST(ut_libsrvkit, parse_zk_url)
{
    // case 1: normal host
    char* host = NULL;
    char* path = NULL;
    char* added_group = NULL;
    parse_zk_url("zk://1.2.3.4:20031/", &host, &path, &added_group);
    ASSERT_TRUE(host);
    ASSERT_TRUE(path);
    ASSERT_TRUE(!added_group);
    ASSERT_TRUE(!strcmp(host, "1.2.3.4:20031"));
    ASSERT_TRUE(!strcmp(path, "/"));
    free(host);
    host = NULL;
    free(path);
    path = NULL;

    // case 2: normal host + path
    parse_zk_url("zk://1.2.3.4:20031/aaaaa", &host, &path, &added_group);
    ASSERT_TRUE(host);
    ASSERT_TRUE(path);
    ASSERT_TRUE(!added_group);
    ASSERT_TRUE(!strcmp(host, "1.2.3.4:20031"));
    ASSERT_TRUE(!strcmp(path, "/aaaaa"));
    free(host);
    host = NULL;
    free(path);
    path = NULL;

    parse_zk_url("zk://1.2.3.4:20031/bbb?", &host, &path, &added_group);
    ASSERT_TRUE(host);
    ASSERT_TRUE(path);
    ASSERT_TRUE(!added_group);
    ASSERT_TRUE(!strcmp(host, "1.2.3.4:20031"));
    ASSERT_TRUE(!strcmp(path, "/bbb"));
    free(host);
    host = NULL;
    free(path);
    path = NULL;

    // case 3: normal host + path + added_group
    parse_zk_url("zk://1.2.3.4:20031/ccc?added_group=x", &host, &path, &added_group);
    ASSERT_TRUE(host);
    ASSERT_TRUE(path);
    ASSERT_TRUE(added_group);
    ASSERT_TRUE(!strcmp(host, "1.2.3.4:20031"));
    ASSERT_TRUE(!strcmp(path, "/ccc"));
    ASSERT_TRUE(!strcmp(added_group, "x"));
    free(host);
    host = NULL;
    free(path);
    path = NULL;
    free(added_group);
    added_group = NULL;

    // case 4: normal host + path + added_group + more
    parse_zk_url("zk://1.2.3.4:20031/ccc?added_group=x&k=v", &host, &path, &added_group);
    ASSERT_TRUE(host);
    ASSERT_TRUE(path);
    ASSERT_TRUE(added_group);
    ASSERT_TRUE(!strcmp(host, "1.2.3.4:20031"));
    ASSERT_TRUE(!strcmp(path, "/ccc"));
    ASSERT_TRUE(!strcmp(added_group, "x"));
    free(host);
    host = NULL;
    free(path);
    path = NULL;
    free(added_group);
    added_group = NULL;

    // case 5: url is null
    parse_zk_url(NULL, &host, &path, &added_group);
    ASSERT_TRUE(!host);
    ASSERT_TRUE(!path);
    ASSERT_TRUE(!added_group);

    // case 6: host is null
    parse_zk_url("zk://1.2.3.4:20031/ccc?added_group=x&k=v", NULL, &path, &added_group);
    ASSERT_TRUE(path);
    ASSERT_TRUE(added_group);
    ASSERT_TRUE(!strcmp(path, "/ccc"));
    ASSERT_TRUE(!strcmp(added_group, "x"));
    free(path);
    path = NULL;
    free(added_group);
    added_group = NULL;

    // case 7: path is null
    parse_zk_url("zk://1.2.3.4:20031/ccc?added_group=x&k=v", &host, NULL, &added_group);
    ASSERT_TRUE(host);
    ASSERT_TRUE(added_group);
    ASSERT_TRUE(!strcmp(host, "1.2.3.4:20031"));
    ASSERT_TRUE(!strcmp(added_group, "x"));
    free(host);
    host = NULL;
    free(added_group);
    added_group = NULL;

    // case 8: added_group is null
    parse_zk_url("zk://1.2.3.4:20031/ccc?added_group=x&k=v", &host, &path, NULL);
    ASSERT_TRUE(host);
    ASSERT_TRUE(path);
    ASSERT_TRUE(!strcmp(host, "1.2.3.4:20031"));
    ASSERT_TRUE(!strcmp(path, "/ccc"));
    free(host);
    host = NULL;
    free(path);
    path = NULL;

    // case 9: all are null
    parse_zk_url(NULL, NULL, NULL,NULL);
}

TEST(ut_libsrvkit, check_is_added_group)
{
    // case 1: empty group
    ASSERT_FALSE(check_is_added_group("a", ""));

    // case 2: single group
    ASSERT_TRUE(check_is_added_group("a", "a"));
    ASSERT_TRUE(check_is_added_group("b", "b"));
    ASSERT_FALSE(check_is_added_group("a", "b"));

    // case 3: multi group
    ASSERT_TRUE(check_is_added_group("x", "x,y,z"));
    ASSERT_TRUE(check_is_added_group("x", "z,x,y"));
    ASSERT_TRUE(check_is_added_group("x", "z,y,x"));
    ASSERT_FALSE(check_is_added_group("a", "z,y,x"));

    // case 4: multi group with same prefix
    ASSERT_FALSE(check_is_added_group("x", "xx,y,z"));
    ASSERT_TRUE(check_is_added_group("x", "xx,y,x"));

    // case 5: null group
    ASSERT_FALSE(check_is_added_group(NULL, "xx,y,x"));

    // case 6: null added_group
    ASSERT_FALSE(check_is_added_group("x", NULL));
}

struct CheckFunctor
{
    CheckFunctor(list<string>& grps) : groups_(grps) {}
    bool operator()(char * sz_content)
    {
        strcpy(sz_content, groups_.front().c_str());
        groups_.pop_front();
        return true;
    }

private:
    list<string>& groups_;
};

TEST(ut_libsrvkit, get_same_group_node)
{
    // added_group is null
    {
        MOCKER(read_file_content)
            .stubs()
            .will(returnValue((char*)NULL));
        list<string> lst;
        CheckFunctor checkor(lst);
        lst.push_back("{\"group\":\"test\"}");
        lst.push_back("{\"group\":\"default\"}");
        lst.push_back("{\"group\":\"default\"}");
        MOCKER(zoo_get)
            .stubs()
            .with(any(), any(), any(), checkWith(checkor), any(), any())
            .will(returnValue((int)ZOK));

        String_vector childrens;
        memset(&childrens, 0, sizeof(String_vector));
        childrens.count = 3;
        childrens.data = (char**)calloc(childrens.count, sizeof(char*));
        childrens.data[0] = strdup("0");
        childrens.data[1] = strdup("1");
        childrens.data[2] = strdup("2");

        // filter-out default group
        String_vector ret;
        get_same_group_node(NULL, "", &childrens, &ret, NULL);
        GlobalMockObject::verify();

        ASSERT_EQ(ret.count, 2);
        ASSERT_TRUE(!strcmp(ret.data[0], "1"));
        ASSERT_TRUE(!strcmp(ret.data[1], "2"));

        free(childrens.data);
    }

    // added_group not null, same group not null
    {
        MOCKER(read_file_content)
            .stubs()
            .will(returnValue((char*)NULL));
        list<string> lst;
        CheckFunctor checkor(lst);
        lst.push_back("{\"group\":\"test\"}");
        lst.push_back("{\"group\":\"default\"}");
        lst.push_back("{\"group\":\"x\"}");
        lst.push_back("{\"group\":\"y\"}");
        lst.push_back("{\"group\":\"default\"}");
        MOCKER(zoo_get)
            .stubs()
            .with(any(), any(), any(), checkWith(checkor), any(), any())
            .will(returnValue((int)ZOK));

        String_vector childrens;
        memset(&childrens, 0, sizeof(String_vector));
        childrens.count = 5;
        childrens.data = (char**)calloc(childrens.count, sizeof(char*));
        childrens.data[0] = strdup("0");
        childrens.data[1] = strdup("1");
        childrens.data[2] = strdup("2");
        childrens.data[3] = strdup("3");
        childrens.data[4] = strdup("4");

        // filter-out default group
        String_vector ret;
        get_same_group_node(NULL, "", &childrens, &ret, "test,x");
        GlobalMockObject::verify();

        ASSERT_EQ(ret.count, 2);
        ASSERT_TRUE(!strcmp(ret.data[0], "1"));
        ASSERT_TRUE(!strcmp(ret.data[1], "4"));

        free(childrens.data);
    }

    // added_group not null, same group is null
    {
        MOCKER(read_file_content)
            .stubs()
            .will(returnValue((char*)NULL));
        list<string> lst;
        CheckFunctor checkor(lst);
        lst.push_back("{\"group\":\"test\"}");
        lst.push_back("{\"group\":\"a\"}");
        lst.push_back("{\"group\":\"x\"}");
        lst.push_back("{\"group\":\"y\"}");
        lst.push_back("{\"group\":\"b\"}");
        MOCKER(zoo_get)
            .stubs()
            .with(any(), any(), any(), checkWith(checkor), any(), any())
            .will(returnValue((int)ZOK));

        String_vector childrens;
        memset(&childrens, 0, sizeof(String_vector));
        childrens.count = 5;
        childrens.data = (char**)calloc(childrens.count, sizeof(char*));
        childrens.data[0] = strdup("0");
        childrens.data[1] = strdup("1");
        childrens.data[2] = strdup("2");
        childrens.data[3] = strdup("3");
        childrens.data[4] = strdup("4");

        // filter-out default group
        String_vector ret;
        get_same_group_node(NULL, "", &childrens, &ret, "b,x,test");
        GlobalMockObject::verify();

        ASSERT_EQ(ret.count, 3);
        ASSERT_TRUE(!strcmp(ret.data[0], "0"));
        ASSERT_TRUE(!strcmp(ret.data[1], "2"));
        ASSERT_TRUE(!strcmp(ret.data[2], "4"));

        free(childrens.data);
    }
}

json_object* root;
bool checkJsonObject(json_object* jso)
{
    root = json_object_get(jso);
    return true;
}

TEST(ut_libsrvkit, mc_collect)
{
    g_app_name = strdup("test");
    strcpy(g_ip, "4.3.2.1");

    worker_thread_t* worker = (worker_thread_t*)calloc(1, sizeof(worker_thread_t));

    // case 1: check major args
    {
        rpc_info_t rpc_info;
        strcpy(rpc_info.service, "my_svr");
        strcpy(rpc_info.method, "my_caller");
        strcpy(rpc_info.ip, "1.2.3.4");
        rpc_info.start_time = get_milli_second();

        MOCKER(util_send_to_elk)
            .stubs()
            .with(eq(LEVEL_LOG_INFO), smirror("rpc"), checkWith(checkJsonObject))
            .will(returnValue(0));

        mc_collect(worker, &rpc_info, 1234, 5678, 0);
        GlobalMockObject::verify();

        json_object* src_service = NULL;
        json_object_object_get_ex(root, "src_service", &src_service);
        const char* str = json_object_get_string(src_service);
        ASSERT_EQ(strcmp(str, g_app_name), 0);

        json_object* dst_service = NULL;
        json_object_object_get_ex(root, "dst_service", &dst_service);
        str = json_object_get_string(dst_service);
        ASSERT_EQ(strcmp(str, rpc_info.service), 0);

        json_object* cmd = NULL;
        json_object_object_get_ex(root, "cmd", &cmd);
        str = json_object_get_string(cmd);
        ASSERT_EQ(strcmp(str, rpc_info.method), 0);

        json_object* src_ip = NULL;
        json_object_object_get_ex(root, "src_ip", &src_ip);
        str = json_object_get_string(src_ip);
        ASSERT_EQ(strcmp(str, g_ip), 0);

        json_object* dst_ip = NULL;
        json_object_object_get_ex(root, "dst_ip", &dst_ip);
        str = json_object_get_string(dst_ip);
        ASSERT_EQ(strcmp(str, rpc_info.ip), 0);

        json_object* caller = NULL;
        json_object_object_get_ex(root, "caller", &caller);
        str = json_object_get_string(caller);
        ASSERT_EQ(strcmp(str, g_app_name), 0);

        json_object* req_time = NULL;
        json_object_object_get_ex(root, "req_time", &req_time);
        ASSERT_EQ(json_object_get_int64(req_time), rpc_info.start_time);

        json_object* resp_time = NULL;
        json_object_object_get_ex(root, "resp_time", &resp_time);
        ASSERT_TRUE(json_object_get_int64(resp_time) - rpc_info.start_time < 1000);

        json_object* cost = NULL;
        json_object_object_get_ex(root, "cost", &cost);
        ASSERT_EQ(json_object_get_int64(cost), json_object_get_int64(resp_time) - json_object_get_int64(req_time));

        json_object* biz_cost = NULL;
        json_object_object_get_ex(root, "biz_cost", &biz_cost);
        ASSERT_EQ(json_object_get_int64(biz_cost), 1234);

        json_object* socket_code = NULL;
        json_object_object_get_ex(root, "socket_code", &socket_code);
        ASSERT_EQ(json_object_get_int64(socket_code), 5678);

        json_object* biz_code = NULL;
        json_object_object_get_ex(root, "biz_code", &biz_code);
        ASSERT_EQ(json_object_get_int64(biz_code), 0);
    }

    // case 2: check other args
    {
        rpc_info_t rpc_info;
        strcpy(rpc_info.service, "my_svr111");
        strcpy(rpc_info.method, "my_caller111");
        strcpy(rpc_info.ip, "1.2.3.41");
        rpc_info.start_time = get_milli_second();

        MOCKER(util_send_to_elk)
            .stubs()
            .with(eq(LEVEL_LOG_INFO), smirror("rpc"), checkWith(checkJsonObject))
            .will(returnValue(0));

        mc_collect(worker, &rpc_info, 1234111, 5678111, 0);
        GlobalMockObject::verify();

        json_object* src_service = NULL;
        json_object_object_get_ex(root, "src_service", &src_service);
        const char* str = json_object_get_string(src_service);
        ASSERT_EQ(strcmp(str, g_app_name), 0);

        json_object* dst_service = NULL;
        json_object_object_get_ex(root, "dst_service", &dst_service);
        str = json_object_get_string(dst_service);
        ASSERT_EQ(strcmp(str, rpc_info.service), 0);

        json_object* cmd = NULL;
        json_object_object_get_ex(root, "cmd", &cmd);
        str = json_object_get_string(cmd);
        ASSERT_EQ(strcmp(str, rpc_info.method), 0);

        json_object* src_ip = NULL;
        json_object_object_get_ex(root, "src_ip", &src_ip);
        str = json_object_get_string(src_ip);
        ASSERT_EQ(strcmp(str, g_ip), 0);

        json_object* dst_ip = NULL;
        json_object_object_get_ex(root, "dst_ip", &dst_ip);
        str = json_object_get_string(dst_ip);
        ASSERT_EQ(strcmp(str, rpc_info.ip), 0);

        json_object* caller = NULL;
        json_object_object_get_ex(root, "caller", &caller);
        str = json_object_get_string(caller);
        ASSERT_EQ(strcmp(str, g_app_name), 0);

        json_object* req_time = NULL;
        json_object_object_get_ex(root, "req_time", &req_time);
        ASSERT_EQ(json_object_get_int64(req_time), rpc_info.start_time);

        json_object* resp_time = NULL;
        json_object_object_get_ex(root, "resp_time", &resp_time);
        ASSERT_TRUE(json_object_get_int64(resp_time) - rpc_info.start_time < 1000);

        json_object* cost = NULL;
        json_object_object_get_ex(root, "cost", &cost);
        ASSERT_EQ(json_object_get_int64(cost), json_object_get_int64(resp_time) - json_object_get_int64(req_time));

        json_object* biz_cost = NULL;
        json_object_object_get_ex(root, "biz_cost", &biz_cost);
        ASSERT_EQ(json_object_get_int64(biz_cost), 1234111);

        json_object* socket_code = NULL;
        json_object_object_get_ex(root, "socket_code", &socket_code);
        ASSERT_EQ(json_object_get_int64(socket_code), 5678111);

        json_object* biz_code = NULL;
        json_object_object_get_ex(root, "biz_code", &biz_code);
        ASSERT_EQ(json_object_get_int64(biz_code), 0);
    }
}