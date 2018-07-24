#include "gtest/gtest.h"
#include "util_base64.h"

#include <string>
using namespace std;

TEST(ut_base64, encode)
{
    // normal cases
    // case 1: empty string
    {
        string str;
        string ret;
        util_base64_encode((unsigned char*)str.data(), str.size(), ret);
        ASSERT_TRUE(ret.empty());
    }

    // case 2: normal string
    {
        string str("The quick fox jumps over a lazy dog.");
        string ret;
        util_base64_encode((unsigned char*)str.data(), str.size(), ret);
        ASSERT_EQ(ret, "VGhlIHF1aWNrIGZveCBqdW1wcyBvdmVyIGEgbGF6eSBkb2cu");
    }

    // case 3: normal string with =
    {
        string str("The quick fox jumps over a lazy dog");
        string ret;
        util_base64_encode((unsigned char*)str.data(), str.size(), ret);
        ASSERT_EQ(ret, "VGhlIHF1aWNrIGZveCBqdW1wcyBvdmVyIGEgbGF6eSBkb2c=");
    }

    // case 4: normal binary buffer
    {
        string str("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A");
        string ret;
        util_base64_encode((unsigned char*)str.data(), str.size(), ret);
        ASSERT_EQ(ret, "AQIDBAUGBwgJCg==");
    }

    // [not support] case 5: new line per 76 chars

    // exceptional cases
    // case 1: null
    {
        string ret;
        //util_base64_encode(NULL, 1111, ret);
        ASSERT_TRUE(ret.empty());
    }

    // case 2: clear input
    {
        string str("The quick fox jumps over a lazy dog.");
        string ret;
        util_base64_encode((unsigned char*)str.data(), 0, ret);
        ASSERT_TRUE(ret.empty());
        util_base64_encode((unsigned char*)str.data(), str.size(), ret);
        ASSERT_EQ(ret, "VGhlIHF1aWNrIGZveCBqdW1wcyBvdmVyIGEgbGF6eSBkb2cu");
    }
}

TEST(ut_base64, decode)
{
    const int buffer_len = 1024;
    char buffer[buffer_len] = {0};
    // normal cases
    // case 1: empty string
    {
        size_t len = 0;
        string str;
        util_base64_decode(str, buffer, &len);
        ASSERT_EQ(len, 0);
    }

    // case 2: normal string
    {
        size_t len = 0;
        string str("VGhlIHF1aWNrIGZveCBqdW1wcyBvdmVyIGEgbGF6eSBkb2cu");
        util_base64_decode(str, buffer, &len);
        string ret("The quick fox jumps over a lazy dog.");
        ASSERT_EQ(len, ret.size());
        ASSERT_TRUE(memcmp(buffer, ret.data(), len) == 0);
    }

    // exceptional cases
    // case 1: null
    {
        size_t len = 0;
        string str("VGhlIHF1aWNrIGZveCBqdW1wcyBvdmVyIGEgbGF6eSBkb2cu");
        util_base64_decode(str, NULL, &len);
        ASSERT_EQ(len, 0);
        buffer[0] = 'a';
        util_base64_decode(str, buffer, NULL);
        ASSERT_EQ(buffer[0], 'a');
    }

    // case 2: length % 4 != 0
    {
        size_t len = 0;
        string str("VGhlIHF1aWNrIGZveCBqdW1wcyBvdmVyIGEgbGF6eSBkb2c");
        util_base64_decode(str, buffer, &len);
        string ret("The quick fox jumps over a lazy dog");
        ASSERT_EQ(len, ret.size());
        ASSERT_TRUE(memcmp(buffer, ret.data(), len) == 0);
    }
}