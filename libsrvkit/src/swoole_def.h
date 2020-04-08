#ifndef __LIBSRVKIT_SWOOLE_DEF_H__
#define __LIBSRVKIT_SWOOLE_DEF_H__

#include <swoole.pb.h>

#define K_SWOOLE_MAGIC 2233
#define K_SWOOLE_REQUEST '0'
#define K_SWOOLE_RESPONSE '1'

typedef struct swoole_head
{
	uint32_t header_magic;
	uint32_t header_ts;
	uint32_t header_check_sum;
	uint32_t header_version;
	uint32_t header_reserved;
	uint32_t header_seq;
	uint32_t header_len;
	char cmd[64];
}swoole_head_t;

void init_swoole_head(swoole_head_t* head, uint32_t version);
void swoole_head_ntohl(swoole_head_t* head);
void swoole_head_htonl(swoole_head_t* head);
void set_swoole_head_cmd(swoole_head_t* head, char type, const char* method);
#endif//__LIBSRVKIT_SWOOLE_DEF_H__

/*
Example:

{
    "header":{
        "platform":"",
        "src":"",
        "version":"",
        "buvid":"AUTO9915283373595582",
        "trace_id":"6c0f936db106dced:6c0f936db106dced:0:0",
        "uid":27682975,
        "caller":"bplus-gw",
        "user_ip":"36.149.215.250",
        "source_group":null
    },
    
    "body":{
        "rsp_type":"1",
        "uid":"27682975",
        "update_num_dy_id":"126656047235344816",
        "type_list":"64",
        "_cb":"cb_07756046839912789"
    },
    "http":{
        "method":"GET",
        "uri":"/dynamic_svr/v1/dynamic_svr/dynamic_num",
        "protocol":"HTTP/1.1",
        "header":{
            "Host":"api.vc.bilibili.com",
            "X-Real-Ip":"36.149.215.250",
            "X-Forwarded-For":"112.25.54.211",
            "X-Track-Id":"1528339310273735539182",
            "X-Sanp-Id":"1528339310273735539182",
            "Accept-Encoding":"gzip",
            "X-Cache-Server":"cn-jsnj3-cmcc-w-01",
            "X-Cache-Server-Addr":"112.25.54.213",
            "X-Cache-Server-Hash":"e8190575f155eeedfafec28d44946c13",
            "X-Backend-Bili-Real-Ip":"36.149.215.250",
            "X-Backend-Bili-Real-Ipport":"31189",
            "X-Backend-Bili-Real-Ip-Chain":"36.149.215.250:31189",
            "X-Scheme":"https",
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36",
            "Accept":"* / *",
            "Referer":"https://www.bilibili.com/video/av24300492/?spm_id_from=333.9.technology_fun.23",
            "Accept-Language":"zh-CN,zh;q=0.8"
        },
        "cookie":{
            "l":"v",
            "finger":"05ae7751",
            "LIVE_BUVID":"AUTO9915283373595582",
            "fts":"1528337354",
            "sid":"bsob6bop",
            "DedeUserID":"27682975",
            "DedeUserID__ckMd5":"20abd030fd7e703a",
            "SESSDATA":"04d33b17,1530929371,cc1a92e3",
            "bili_jct":"54416a09ce55b0e33d5d7164ef3a2664",
            "buvid3":"10779253-FBE2-4860-9BAC-9EA1123BD94541861infoc",
            "rpdid":"xokmxmoxidosiqkkmkpw",
            "CURRENT_QUALITY":"80",
            "bp_t_offset_27682975":"126656047235344816",
            "_dfcaptcha":"782a43956cb068303d0d542e6070659d"
        },
        "body":null,
        "is_https":1,
        "uri_with_params":"/dynamic_svr/v1/dynamic_svr/dynamic_num?rsp_type=1&uid=27682975&update_num_dy_id=126656047235344816&type_list=64&_cb=cb_07756046839912789"
    }
}
*/
