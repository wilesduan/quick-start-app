#include "gtest/gtest.h"
#include "util_file.h"

#include <iostream>
#include <list>
using namespace std;

#include "mockcpp/mockcpp.hpp"

struct CheckFunctor
{
    CheckFunctor(list<string> &dirs) : dirs_(dirs) {}
    bool operator()(const char * dir)
    {
        return dirs_.front() == dir;
    }

private:
    list<string> & dirs_;
};

static list<string> random_input_dirs;
struct RandomInputFunctor
{
    static int my_access(const char * dir, int mode)
    {
        if(rand() % 2) {
            random_input_dirs.push_front(dir);
            return 1;
        }
        return 0;
    }
};

struct MkdirCheckFunctor
{
    MkdirCheckFunctor(list<string> &dirs) : dirs_(dirs) {}
    bool operator()(const char * dir)
    {
        if(dirs_.front() == dir) {
            dirs_.pop_front();
            return true;
        }
        return false;
    }

private:
    list<string> & dirs_;
};

TEST(ut_file, create_dir)
{
    srand(time(0));

    list<string> dirs;
    MOCKER(access)
        .stubs()
        .with(checkWith(CheckFunctor(dirs)))
        .will(returnValue(1));
    MOCKER(mkdir)
        .stubs()
        .with(checkWith(MkdirCheckFunctor(dirs)))
        .will(returnValue(0));

    dirs.push_back("/a");
    dirs.push_back("/a/b");
    dirs.push_back("/a/b/c");
    dirs.push_back("/a/b/c/d");
    dirs.push_back("/a/b/c/d/e");

    ASSERT_TRUE(create_dir("/a/b/c/d/e", 0744) == 0);
    ASSERT_TRUE(dirs.empty());

    GlobalMockObject::verify();

    MOCKER(access)
        .stubs()
        .with(any())
        .will(invoke(RandomInputFunctor::my_access));

    random_input_dirs.push_back("/a/b/c/d/e");
    MOCKER(mkdir)
        .stubs()
        .with(checkWith(MkdirCheckFunctor(random_input_dirs)))
        .will(returnValue(0));

    ASSERT_TRUE(create_dir("/a/b/c/d/e", 0744) == 0);
    ASSERT_TRUE(random_input_dirs.empty());

    GlobalMockObject::verify();
}