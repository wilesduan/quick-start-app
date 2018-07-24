#include <gtest/gtest.h>
#include <mockcpp/mockcpp.hpp>
#include "server.h"
#include "mysql_wrapper.h"

#include <gen_test_svr.pb.h>

#define private public
#include "util_borm.h"
#undef private

using namespace borm;

std::vector<std::string> sqls;

struct person
{
    int64_t  id;
    float    score;
    int      weight;
    bool     gender;
    std::string   name;
    std::string   ctime;

    borm(id | score | weight | gender | name | ctime)
};

struct person_stats
{
    int64_t  count;

    borm(count)
};

struct SqlCommandCheckor
{
    bool operator() (const char* sql) {
        sqls.push_back(sql);
        return true;
    }
};

TEST(borm, insert)
{
    coroutine_t co;
    rpc_ctx_t ctx;
    ctx.co = &co;
    mysql_query_t query = {0};
    // 正常用例
    MOCKER(util_write_log)
        .stubs();
    MOCKER(get_mysql_from_rpc_by_id)
        .stubs()
        .will(returnValue((MYSQL*)1));
    MOCKER(mysql_malloc_query)
        .stubs()
        .with(any(), any(), checkWith(SqlCommandCheckor()))
        .will(returnValue(&query));
    MOCKER(execute_mysql_query)
        .stubs()
        .will(returnValue(0));
    MOCKER(mysql_free_query)
        .stubs();

    table t(&ctx, "db", "tbl");

    person p = {1, 20.1, 80, true, "orca", "2018-7-2 00:00:00"};
    // 单参数插入
    t.insert(p);
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`,`gender`,`name`,`ctime`) values (1,20.1,80,1,'orca','2018-7-2 00:00:00')");
    sqls.clear();

    // 附带filter
    t.insert(p, borm_f(id|score|weight));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`) values (1,20.1,80)");
    sqls.clear();

    // 附带filter rename
    t.insert(p, borm_f(id _as_ "pid"));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`pid`) values (1)");
    sqls.clear();

    // 附带filter和ext
    t.insert(p, borm_f(id|score|weight), "on duplicate key update `status`=1");
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`) values (1,20.1,80) on duplicate key update `status`=1");
    sqls.clear();

    // 附带filter（含不存在的）和ext
    t.insert(p, borm_f(id|score|weights), "on duplicate key update `status`=1");
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`) values (1,20.1) on duplicate key update `status`=1");
    sqls.clear();

    // 附带on_duplicate_key_update（filter）
    t.insert(p, on_duplicate_key_update(borm_f(weight)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`,`gender`,`name`,`ctime`) values (1,20.1,80,1,'orca','2018-7-2 00:00:00') on duplicate key update `weight`=80");
    sqls.clear();

    // 附带on_duplicate_key_update（filter）（含不存在的）
    t.insert(p, on_duplicate_key_update(borm_f(weights)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`,`gender`,`name`,`ctime`) values (1,20.1,80,1,'orca','2018-7-2 00:00:00')");
    sqls.clear();

    // 附带on_duplicate_key_update（filter和ext）
    t.insert(p, on_duplicate_key_update(borm_f(weight), "`status`=1"));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`,`gender`,`name`,`ctime`) values (1,20.1,80,1,'orca','2018-7-2 00:00:00') on duplicate key update `weight`=80,`status`=1");
    sqls.clear();

    // 附带on_duplicate_key_update（ext）
    t.insert(p, on_duplicate_key_update(borm_f(weights), "`status`=1"));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`,`gender`,`name`,`ctime`) values (1,20.1,80,1,'orca','2018-7-2 00:00:00') on duplicate key update `status`=1");
    sqls.clear();

    // 附带filter和on_duplicate_key_update（filter）
    t.insert(p, borm_f(id|score|weight), on_duplicate_key_update(borm_f(weight)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`) values (1,20.1,80) on duplicate key update `weight`=80");
    sqls.clear();

    // 附带filter和on_duplicate_key_update（filter）（含不存在的）
    t.insert(p, borm_f(id|score|weight), on_duplicate_key_update(borm_f(weights)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`) values (1,20.1,80)");
    sqls.clear();

    // 附带filter和on_duplicate_key_update（filter和ext）
    t.insert(p, borm_f(id|score|weight), on_duplicate_key_update(borm_f(weight), "`status`=1"));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`) values (1,20.1,80) on duplicate key update `weight`=80,`status`=1");
    sqls.clear();

    // 附带filter和on_duplicate_key_update（ext）
    t.insert(p, borm_f(id|score|weight), on_duplicate_key_update(borm_f(weights), "`status`=1"));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`) values (1,20.1,80) on duplicate key update `status`=1");
    sqls.clear();

    // 附带filter（含不存在的）和on_duplicate_key_update（filter）
    t.insert(p, borm_f(id|score|weights), on_duplicate_key_update(borm_f(weight)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`) values (1,20.1) on duplicate key update `weight`=80");
    sqls.clear();

    // 附带filter（含不存在的）和on_duplicate_key_update（filter）（含不存在的）
    t.insert(p, borm_f(id|score|weights), on_duplicate_key_update(borm_f(weights)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`) values (1,20.1)");
    sqls.clear();

    // 附带filter（含不存在的）和on_duplicate_key_update（filter和ext）
    t.insert(p, borm_f(id|score|weights), on_duplicate_key_update(borm_f(weight), "`status`=1"));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`) values (1,20.1) on duplicate key update `weight`=80,`status`=1");
    sqls.clear();

    // 附带filter（含不存在的）和on_duplicate_key_update（ext）
    t.insert(p, borm_f(id|score|weights), on_duplicate_key_update(borm_f(weights), "`status`=1"));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`) values (1,20.1) on duplicate key update `status`=1");
    sqls.clear();

    // 指针方式插入
    t.insert(&p);
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`,`gender`,`name`,`ctime`) values (1,20.1,80,1,'orca','2018-7-2 00:00:00')");
    sqls.clear();

    ////////////////////////////////////////////////////////////
    /// 数组方式插入
    person o = {2, 99.9, 120, true, "neowei", "2018-7-3 00:00:00"};
    std::vector<person> ps;
    ps.push_back(p);
    ps.push_back(o);
    // 单参数插入
    t.insert(ps);
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`,`gender`,`name`,`ctime`) values (1,20.1,80,1,'orca','2018-7-2 00:00:00'), (2,99.9,120,1,'neowei','2018-7-3 00:00:00')");
    sqls.clear();

    // 附带filter
    t.insert(ps, borm_f(id|score|weight));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`) values (1,20.1,80), (2,99.9,120)");
    sqls.clear();

    // 附带filter（重命名）
    t.insert(ps, borm_f(id _as_ "pid"|score|weight));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`pid`,`score`,`weight`) values (1,20.1,80), (2,99.9,120)");
    sqls.clear();

    // 附带filter和ext
    t.insert(ps, borm_f(id|score|weight), "on duplicate key update `status`=1");
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`) values (1,20.1,80), (2,99.9,120) on duplicate key update `status`=1");
    sqls.clear();

    // 附带filter（含不存在的）和ext
    t.insert(ps, borm_f(id|score|weights), "on duplicate key update `status`=1");
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`) values (1,20.1), (2,99.9) on duplicate key update `status`=1");
    sqls.clear();

    // 指针方式插入
    t.insert(&ps);
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`,`gender`,`name`,`ctime`) values (1,20.1,80,1,'orca','2018-7-2 00:00:00'), (2,99.9,120,1,'neowei','2018-7-3 00:00:00')");
    sqls.clear();

    test::Req req;
    req.set_id(1);
    req.set_score(20.1);
    req.set_weight(80);
    req.set_gender(1);
    req.set_name("orca");
    req.set_ctime("2018-7-2 00:00:00");

    // 单参数插入
    t.insert(req);
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`,`gender`,`name`,`ctime`) values (1,20.1,80,1,'orca','2018-7-2 00:00:00')");
    sqls.clear();

    // 附带filter
    t.insert(req, borm_f(id|score|weight));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`) values (1,20.1,80)");
    sqls.clear();

    // 附带filter（重命名）
    t.insert(req, borm_f(id _as_ "pid"|score|weight));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`pid`,`score`,`weight`) values (1,20.1,80)");
    sqls.clear();

    // 附带filter和ext
    t.insert(req, borm_f(id|score|weight), "on duplicate key update `status`=1");
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`) values (1,20.1,80) on duplicate key update `status`=1");
    sqls.clear();

    // 附带filter（含不存在的）和ext
    /*t.insert(req, borm_f(id|score|weights), "on duplicate key update `status`=1");
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`) values (1,20.1) on duplicate key update `status`=1");
    sqls.clear();*/

    // 附带on_duplicate_key_update（filter）
    t.insert(req, on_duplicate_key_update(borm_f(weight)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`,`gender`,`name`,`ctime`) values (1,20.1,80,1,'orca','2018-7-2 00:00:00') on duplicate key update `weight`=80");
    sqls.clear();

    // 附带on_duplicate_key_update（filter）（含不存在的）
    /*t.insert(req, on_duplicate_key_update(borm_f(weights)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`,`gender`,`name`,`ctime`) values (1,20.1,80,1,'orca','2018-7-2 00:00:00')");
    sqls.clear();*/

    // 附带on_duplicate_key_update（filter和ext）
    t.insert(req, on_duplicate_key_update(borm_f(weight), "`status`=1"));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`,`gender`,`name`,`ctime`) values (1,20.1,80,1,'orca','2018-7-2 00:00:00') on duplicate key update `weight`=80,`status`=1");
    sqls.clear();

    // 附带on_duplicate_key_update（ext）
    /*t.insert(req, on_duplicate_key_update(borm_f(weights), "`status`=1"));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`,`gender`,`name`,`ctime`) values (1,20.1,80,1,'orca','2018-7-2 00:00:00') on duplicate key update `status`=1");
    sqls.clear();*/

    // 附带filter和on_duplicate_key_update（filter）
    t.insert(req, borm_f(id|score|weight), on_duplicate_key_update(borm_f(weight)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`) values (1,20.1,80) on duplicate key update `weight`=80");
    sqls.clear();

    // 附带filter和on_duplicate_key_update（filter）（含不存在的）
    t.insert(req, borm_f(id|score|weight), on_duplicate_key_update(borm_f(weights)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`) values (1,20.1,80)");
    sqls.clear();

    // 附带filter和on_duplicate_key_update（filter和ext）
    t.insert(req, borm_f(id|score|weight), on_duplicate_key_update(borm_f(weight), "`status`=1"));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`) values (1,20.1,80) on duplicate key update `weight`=80,`status`=1");
    sqls.clear();

    // 附带filter和on_duplicate_key_update（ext）
    t.insert(req, borm_f(id|score|weight), on_duplicate_key_update(borm_f(weights), "`status`=1"));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`) values (1,20.1,80) on duplicate key update `status`=1");
    sqls.clear();

    // 附带filter（含不存在的）和on_duplicate_key_update（filter）
    /*t.insert(req, borm_f(id|score|weights), on_duplicate_key_update(borm_f(weight)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`) values (1,20.1) on duplicate key update `weight`=80");
    sqls.clear();

    // 附带filter（含不存在的）和on_duplicate_key_update（filter）（含不存在的）
    t.insert(req, borm_f(id|score|weights), on_duplicate_key_update(borm_f(weights)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`) values (1,20.1)");
    sqls.clear();

    // 附带filter（含不存在的）和on_duplicate_key_update（filter和ext）
    t.insert(req, borm_f(id|score|weights), on_duplicate_key_update(borm_f(weight), "`status`=1"));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`) values (1,20.1) on duplicate key update `weight`=80,`status`=1");
    sqls.clear();

    // 附带filter（含不存在的）和on_duplicate_key_update（ext）
    t.insert(req, borm_f(id|score|weights), on_duplicate_key_update(borm_f(weights), "`status`=1"));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`) values (1,20.1) on duplicate key update `status`=1");
    sqls.clear();*/

    // 指针方式插入
    t.insert(&req);
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`,`gender`,`name`,`ctime`) values (1,20.1,80,1,'orca','2018-7-2 00:00:00')");
    sqls.clear();

    ////////////////////////////////////////////////////////////
    /// 数组方式插入
    test::ReqBatch reqBatch;
    test::Req* preq = reqBatch.add_batch();
    preq->set_id(1);
    preq->set_score(20.1);
    preq->set_weight(80);
    preq->set_gender(1);
    preq->set_name("orca");
    preq->set_ctime("2018-7-2 00:00:00");
    preq = reqBatch.add_batch();
    preq->set_id(2);
    preq->set_score(99.9);
    preq->set_weight(120);
    preq->set_gender(1);
    preq->set_name("neowei");
    preq->set_ctime("2018-7-3 00:00:00");

    // 单参数插入
    t.insert(reqBatch.batch());
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`,`gender`,`name`,`ctime`) values (1,20.1,80,1,'orca','2018-7-2 00:00:00'), (2,99.9,120,1,'neowei','2018-7-3 00:00:00')");
    sqls.clear();

    // 附带filter
    t.insert(reqBatch.batch(), borm_f(id|score|weight));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`) values (1,20.1,80), (2,99.9,120)");
    sqls.clear();

    // 附带filter和ext
    t.insert(reqBatch.batch(), borm_f(id|score|weight), "on duplicate key update `status`=1");
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`) values (1,20.1,80), (2,99.9,120) on duplicate key update `status`=1");
    sqls.clear();

    // 附带filter（含不存在的）和ext
    /*t.insert(reqBatch.batch(), borm_f(id|score|weights), "on duplicate key update `status`=1");
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`) values (1,20.1), (2,99.9) on duplicate key update `status`=1");
    sqls.clear();*/

    // 指针方式插入
    t.insert(&reqBatch.batch());
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`,`gender`,`name`,`ctime`) values (1,20.1,80,1,'orca','2018-7-2 00:00:00'), (2,99.9,120,1,'neowei','2018-7-3 00:00:00')");
    sqls.clear();

    // 指针方式插入
    t.insert(reqBatch.mutable_batch());
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "insert into `tbl` (`id`,`score`,`weight`,`gender`,`name`,`ctime`) values (1,20.1,80,1,'orca','2018-7-2 00:00:00'), (2,99.9,120,1,'neowei','2018-7-3 00:00:00')");
    sqls.clear();
}

TEST(borm, update)
{
    coroutine_t co;
    rpc_ctx_t ctx;
    ctx.co = &co;
    mysql_query_t query = {0};
    // 正常用例
    MOCKER(util_write_log)
        .stubs();
    MOCKER(get_mysql_from_rpc_by_id)
        .stubs()
        .will(returnValue((MYSQL*)1));
    MOCKER(mysql_malloc_query)
        .stubs()
        .with(any(), any(), checkWith(SqlCommandCheckor()))
        .will(returnValue(&query));
    MOCKER(execute_mysql_query)
        .stubs()
        .will(returnValue(0));
    MOCKER(mysql_free_query)
        .stubs();

    table t(&ctx, "db", "tbl");

    person p = {1, 20.1, 80, true, "orca", "2018-7-2 00:00:00"};
    // 单参数更新
    t.update(p, where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "update `tbl` set `id`=1,`score`=20.1,`weight`=80,`gender`=1,`name`='orca',`ctime`='2018-7-2 00:00:00' where `id`=0");
    sqls.clear();

    // 附带filter
    t.update(p, borm_f(id|score|weight), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "update `tbl` set `id`=1,`score`=20.1,`weight`=80 where `id`=0");
    sqls.clear();

    // 附带filter（重命名）
    t.update(p, borm_f(id _as_ "pid"|score|weight), where(eq(pid, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "update `tbl` set `pid`=1,`score`=20.1,`weight`=80 where `pid`=0");
    sqls.clear();

    // 附带filter（含不存在的）
    t.update(p, borm_f(id|score|weights), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "update `tbl` set `id`=1,`score`=20.1 where `id`=0");
    sqls.clear();

    // 指针方式更新
    // 单参数更新
    t.update(&p, where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "update `tbl` set `id`=1,`score`=20.1,`weight`=80,`gender`=1,`name`='orca',`ctime`='2018-7-2 00:00:00' where `id`=0");
    sqls.clear();

    // 指针方式更新
    // 附带filter
    t.update(&p, borm_f(id|score|weight), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "update `tbl` set `id`=1,`score`=20.1,`weight`=80 where `id`=0");
    sqls.clear();

    // 指针方式更新
    // 附带filter（含不存在的）
    t.update(&p, borm_f(id|score|weights), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "update `tbl` set `id`=1,`score`=20.1 where `id`=0");
    sqls.clear();

    // 附带set_kvs
    t.update(set_kvs("`id`=1,`score`=20.1"), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "update `tbl` set `id`=1,`score`=20.1 where `id`=0");
    sqls.clear();

    // 空set_kvs
    ASSERT_EQ(t.update(set_kvs(""), where(eq(id, 0))), 0);
    ASSERT_EQ(sqls.size(), 0);

    test::Req req;
    req.set_id(1);
    req.set_score(20.1);
    req.set_weight(80);
    req.set_gender(1);
    req.set_name("orca");
    req.set_ctime("2018-7-2 00:00:00");

    // 单参数更新
    t.update(req, where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "update `tbl` set `id`=1,`score`=20.1,`weight`=80,`gender`=1,`name`='orca',`ctime`='2018-7-2 00:00:00' where `id`=0");
    sqls.clear();

    // 附带filter
    t.update(req, borm_f(id|score|weight), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "update `tbl` set `id`=1,`score`=20.1,`weight`=80 where `id`=0");
    sqls.clear();

    // 附带filter（重命名）
    t.update(req, borm_f(id _as_ "pid"|score|weight), where(eq(pid, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "update `tbl` set `pid`=1,`score`=20.1,`weight`=80 where `pid`=0");
    sqls.clear();

    // 附带filter（含不存在的）
    t.update(req, borm_f(id|score|weights), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "update `tbl` set `id`=1,`score`=20.1 where `id`=0");
    sqls.clear();

    // 指针方式更新
    // 单参数更新
    t.update(&req, where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "update `tbl` set `id`=1,`score`=20.1,`weight`=80,`gender`=1,`name`='orca',`ctime`='2018-7-2 00:00:00' where `id`=0");
    sqls.clear();

    // 指针方式更新
    // 附带filter
    t.update(&req, borm_f(id|score|weight), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "update `tbl` set `id`=1,`score`=20.1,`weight`=80 where `id`=0");
    sqls.clear();

    // 指针方式更新
    // 附带filter（含不存在的）
    /*t.update(&req, borm_f(id|score|weights), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "update `tbl` set `id`=1,`score`=20.1 where `id`=0");
    sqls.clear();*/
}

TEST(borm, del)
{
    coroutine_t co;
    rpc_ctx_t ctx;
    ctx.co = &co;
    mysql_query_t query = {0};
    // 正常用例
    MOCKER(util_write_log)
        .stubs();
    MOCKER(get_mysql_from_rpc_by_id)
        .stubs()
        .will(returnValue((MYSQL*)1));
    MOCKER(mysql_malloc_query)
        .stubs()
        .with(any(), any(), checkWith(SqlCommandCheckor()))
        .will(returnValue(&query));
    MOCKER(execute_mysql_query)
        .stubs()
        .will(returnValue(0));
    MOCKER(mysql_free_query)
        .stubs();

    table t(&ctx, "db", "tbl");

    ASSERT_EQ(t.del(where_cond("")), -10002);
    ASSERT_EQ(sqls.size(), 0);

    ASSERT_EQ(t.del(where(eq(id, 0))), 0);
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "delete from `tbl` where `id`=0");
    sqls.clear();
}

TEST(borm, select)
{
    coroutine_t co;
    rpc_ctx_t ctx;
    ctx.co = &co;
    mysql_query_t query = {0};
    // 正常用例
    MOCKER(util_write_log)
        .stubs();
    MOCKER(get_mysql_from_rpc_by_id)
        .stubs()
        .will(returnValue((MYSQL*)1));
    MOCKER(mysql_malloc_query)
        .stubs()
        .with(any(), any(), checkWith(SqlCommandCheckor()))
        .will(returnValue(&query));
    MOCKER(execute_query)
        .stubs()
        .will(returnValue(-1));
    MOCKER(mysql_free_query)
        .stubs();

    table t(&ctx, "db", "tbl");

    // 不含ext测试
    person p;
    // 单参数更新
    t.select(&p, where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "select `id`,`score`,`weight`,`gender`,`name`,`ctime` from `tbl` where `id`=0");
    sqls.clear();

    // 附带filter
    t.select(&p, borm_f(id|score|weight), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "select `id`,`score`,`weight` from `tbl` where `id`=0");
    sqls.clear();

    // 附带filter rename
    t.select(&p, borm_f(id _as_ "pid"), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "select `pid` from `tbl` where `id`=0");
    sqls.clear();

    t.select(&p, borm_f(id _as_ "distinct pid"), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "select distinct pid from `tbl` where `id`=0");
    sqls.clear();

    person_stats pstats;
    // 附带filter rename
    t.select(&pstats, borm_f(count _as_ "count(1)"), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "select count(1) from `tbl` where `id`=0");
    sqls.clear();

    // 附带filter（含不存在的）
    t.select(&p, borm_f(id|score|weights), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "select `id`,`score` from `tbl` where `id`=0");
    sqls.clear();

    test::Req req;
    // 单参数更新
    t.select(&req, where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "select `id`,`score`,`weight`,`gender`,`name`,`ctime` from `tbl` where `id`=0");
    sqls.clear();

    // 附带filter
    t.select(&req, borm_f(id|score|weight), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "select `id`,`score`,`weight` from `tbl` where `id`=0");
    sqls.clear();

    // 附带filter（重命名）
    t.select(&req, borm_f(id _as_ "pid"|score|weight), where(eq(pid, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "select `pid`,`score`,`weight` from `tbl` where `pid`=0");
    sqls.clear();

    /*// 附带filter（含不存在的）
    t.select(&req, borm_f(id|score|weights), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "select `id`,`score` from `tbl` where `id`=0");
    sqls.clear();*/

    /////////////////////////////
    /// 数组
    
    std::vector<person> ps;
    // 单参数更新
    t.select(&ps, where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "select `id`,`score`,`weight`,`gender`,`name`,`ctime` from `tbl` where `id`=0");
    sqls.clear();

    // 附带filter
    t.select(&ps, borm_f(id|score|weight), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "select `id`,`score`,`weight` from `tbl` where `id`=0");
    sqls.clear();

    // 附带filter（含不存在的）
    /*t.select(&ps, borm_f(id|score|weights), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "select `id`,`score` from `tbl` where `id`=0");
    sqls.clear();*/

    test::ReqBatch reqBatch;
    // 单参数更新
    t.select(reqBatch.mutable_batch(), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "select `id`,`score`,`weight`,`gender`,`name`,`ctime` from `tbl` where `id`=0");
    sqls.clear();

    // 附带filter
    t.select(reqBatch.mutable_batch(), borm_f(id|score|weight), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "select `id`,`score`,`weight` from `tbl` where `id`=0");
    sqls.clear();

    // 附带filter（含不存在的）
    /*t.select(reqBatch.mutable_batch(), borm_f(id|score|weights), where(eq(id, 0)));
    ASSERT_EQ(sqls.size(), 1);
    ASSERT_EQ(sqls[0], "select `id`,`score` from `tbl` where `id`=0");
    sqls.clear();*/
}

TEST(borm, where_cond)
{
    where_cond c("");
    ASSERT_EQ(c.str(), "");

    c = where(eq(id, 0));
    ASSERT_EQ(c.str(), " where `id`=0");

    c = where(eq(id, 0) && eq(id, 1) && eq(id, 2));
    ASSERT_EQ(c.str(), " where `id`=0 and `id`=1 and `id`=2");
    c = where((eq(id, 0) && eq(id, 1)) && eq(id, 2));
    ASSERT_EQ(c.str(), " where `id`=0 and `id`=1 and `id`=2");
    c = where(eq(id, 0) && (eq(id, 1) && eq(id, 2)));
    ASSERT_EQ(c.str(), " where `id`=0 and `id`=1 and `id`=2");

    c = where(eq(id, 0) && eq(id, 1) || eq(id, 2));
    ASSERT_EQ(c.str(), " where `id`=0 and `id`=1 or `id`=2");
    c = where((eq(id, 0) && eq(id, 1)) || eq(id, 2));
    ASSERT_EQ(c.str(), " where `id`=0 and `id`=1 or `id`=2");
    c = where(eq(id, 0) && (eq(id, 1) || eq(id, 2)));
    ASSERT_EQ(c.str(), " where `id`=0 and (`id`=1 or `id`=2)");

    c = where(eq(id, 0) || eq(id, 1) && eq(id, 2));
    ASSERT_EQ(c.str(), " where `id`=0 or `id`=1 and `id`=2");
    c = where((eq(id, 0) || eq(id, 1)) && eq(id, 2));
    ASSERT_EQ(c.str(), " where (`id`=0 or `id`=1) and `id`=2");
    c = where(eq(id, 0) || (eq(id, 1) && eq(id, 2)));
    ASSERT_EQ(c.str(), " where `id`=0 or `id`=1 and `id`=2");

    c = where(eq(id, 0) || eq(id, 1) || eq(id, 2));
    ASSERT_EQ(c.str(), " where `id`=0 or `id`=1 or `id`=2");
    c = where((eq(id, 0) || eq(id, 1)) || eq(id, 2));
    ASSERT_EQ(c.str(), " where `id`=0 or `id`=1 or `id`=2");
    c = where(eq(id, 0) || (eq(id, 1) || eq(id, 2)));
    ASSERT_EQ(c.str(), " where `id`=0 or `id`=1 or `id`=2");

    c = where(cond("id!=1 and weight=2 and score>3"));
    ASSERT_EQ(c.str(), " where id!=1 and weight=2 and score>3");

    c = where(nz(id) && cond("(id!=0 or ctime!=0) or score=0"));
    ASSERT_EQ(c.str(), " where `id`!=0 and ((id!=0 or ctime!=0) or score=0)");


    cond status_cond(eq(status, 1) || ge(status, 3));
    cond cc;
    cc = cc && status_cond;
    ASSERT_EQ(cc.str(), "`status`=1 or `status`>=3");
}

TEST(borm, where_ext)
{
    where_ext e;
    ASSERT_EQ(e.str(), "");

    where_ext ext("group by `id`");
    ASSERT_EQ(ext.str(), " group by `id`");

    ext = group_by("id,name");
    ASSERT_EQ(ext.str(), " group by id,name");
    ext = group_by("");
    ASSERT_EQ(ext.str(), "");
    ext = group_by(borm_f(id|name));
    ASSERT_EQ(ext.str(), " group by `id`,`name`");

    ext = order_by("id,name desc");
    ASSERT_EQ(ext.str(), " order by id,name desc");
    ext = order_by(desc(borm_f(id|name)));
    ASSERT_EQ(ext.str(), " order by `id` desc,`name` desc");
    ext = order_by(desc(borm_f(id|name)).asc(borm_f(ctime)));
    ASSERT_EQ(ext.str(), " order by `id` desc,`name` desc,`ctime` asc");

    ext = limit(100);
    ASSERT_EQ(ext.str(), " limit 100");
    ext = limit(1000, 100);
    ASSERT_EQ(ext.str(), " limit 1000,100");

    ext = group_by(borm_f(id|name)).order_by(desc(borm_f(id|name)).asc(borm_f(ctime))).limit(1000, 100);
    ASSERT_EQ(ext.str(), " group by `id`,`name` order by `id` desc,`name` desc,`ctime` asc limit 1000,100");
    ext = group_by(borm_f(id|name)).order_by(desc(borm_f(id|name)).asc(borm_f(ctime))).limit(100);
    ASSERT_EQ(ext.str(), " group by `id`,`name` order by `id` desc,`name` desc,`ctime` asc limit 100");
    ext = group_by("").order_by(desc(borm_f(id|name)).asc(borm_f(ctime))).limit(1000, 100);
    ASSERT_EQ(ext.str(), " order by `id` desc,`name` desc,`ctime` asc limit 1000,100");
    ext = group_by("").order_by(desc(borm_f(id|name)).asc(borm_f(ctime))).limit(100);
    ASSERT_EQ(ext.str(), " order by `id` desc,`name` desc,`ctime` asc limit 100");
    ext = group_by(borm_f(id|name)).limit(1000, 100);
    ASSERT_EQ(ext.str(), " group by `id`,`name` limit 1000,100");
    ext = group_by(borm_f(id|name)).limit(100);
    ASSERT_EQ(ext.str(), " group by `id`,`name` limit 100");
}
