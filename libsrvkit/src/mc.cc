
#include <server_inner.h>

extern char g_ip[24];
extern char* g_app_name;

static void do_report_mc(worker_thread_t* worker, blink::collect_request* collector)
{
	proto_client_t* clients = get_clients_by_service(worker, "mc_agent_svr");
	if(NULL == clients || !clients->num_clients){
		return;
	}

	blink::MsgBody body;
	body.set_call_type(blink::EN_MSG_TYPE_REQUEST);
	body.set_service("mc_agent_svr");
	body.set_method(1);
	std::string payload;
	collector->SerializeToString(&payload);
	body.set_payload(payload.data(), payload.size());
	std::string udp_packet;
	body.SerializeToString(&udp_packet);

	int idx = random()%(clients->num_clients);
	proto_client_inst_t* inst = clients->cli_inst_s + idx;
	ev_ptr_t* ptr = inst->ptr;
	int fd = ptr->fd;
	send(fd, udp_packet.data(), udp_packet.size(), 0);
	LOG_DBG("report to mc size:%llu, %s:%d", collector->new_items_size(), ptr->ip, ptr->port);
}

void mc_collect(worker_thread_t* worker, rpc_info_t* rpc_info, int cost, int code, int acc, const char* ss_trace_id_s)
{
	uint64_t now = get_milli_second();
	if(!worker->pb_mc_collector){
		worker->pb_mc_collector = new blink::collect_request();
		((blink::collect_request*)(worker->pb_mc_collector))->set_last_report_time(now);
	}

	blink::collect_request* collector = (blink::collect_request*)(worker->pb_mc_collector);

	blink::mc_stat_item* item = collector->add_new_items();
	item->set_src_service(g_app_name);
	item->set_dst_service(rpc_info->service);
	item->set_cmd(rpc_info->method);
	item->set_src_ip(g_ip);
	item->set_dst_ip(rpc_info->ip);
	item->set_caller(g_app_name);
	item->set_req_time(rpc_info->start_time);
	item->set_resp_time(now);
	item->set_biz_cost(cost);
	item->set_socket_code(code);
	item->set_biz_code(0);

	if(collector->new_items_size() > 100 || now - collector->last_report_time() > 60000){
		do_report_mc(worker, collector);
		collector->Clear();
		collector->set_last_report_time(now);
	}

	json_object* root = json_object_new_object();
	json_object_object_add(root, "src_service", json_object_new_string(g_app_name));
	json_object_object_add(root, "dst_service", json_object_new_string(rpc_info->service));
	json_object_object_add(root, "cmd",         json_object_new_string(rpc_info->method));
	json_object_object_add(root, "src_ip",      json_object_new_string(g_ip));
	json_object_object_add(root, "dst_ip",      json_object_new_string(rpc_info->ip));
	json_object_object_add(root, "caller",      json_object_new_string(g_app_name));
	json_object_object_add(root, "req_time",    json_object_new_int64(rpc_info->start_time));
	json_object_object_add(root, "resp_time",   json_object_new_int64(now));
	json_object_object_add(root, "cost",        json_object_new_int(now - rpc_info->start_time));
	json_object_object_add(root, "biz_cost",    json_object_new_int(cost));
	json_object_object_add(root, "socket_code", json_object_new_int(code));
	json_object_object_add(root, "biz_code",    json_object_new_int(0));
	if(ss_trace_id_s)
		json_object_object_add(root, "trace_id", json_object_new_string(ss_trace_id_s));

	util_send_to_elk(LEVEL_LOG_INFO, "rpc", root);
    if(root) json_object_put(root);

	if(acc){
		char sz_key[100];
		sz_key[99] = 0;

		snprintf(sz_key, 99, "qpm_%s_%s", rpc_info->service, rpc_info->method);
		MONITOR_ACC(sz_key, 1);

		snprintf(sz_key, 99, "cost_%s_%s", rpc_info->service, rpc_info->method);
		MONITOR_ACC(sz_key, now-rpc_info->start_time);
	}
}
