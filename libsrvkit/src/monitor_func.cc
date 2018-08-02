#include <google/protobuf/message.h>
#include <blink.pb.h>
#include <time.h>
#include <string>

#include <bim_util.h>

int fn_update_monitor_info(int udp_fd, const struct sockaddr *dest_addr, socklen_t addrlen, const char* service, const std::map<std::string, int>& monitor_infos)
{
	if(udp_fd <= 0){
		LOG_ERR("invalid udp fd:%d", udp_fd);
		return 0;
	}

	time_t now = time(NULL);
	blink::ReqAddMonitorLog req;
	for(std::map<std::string, int>::const_iterator it = monitor_infos.begin(); it != monitor_infos.end(); ++it){
		blink::MonitorDataInner* item = req.add_monitor_log();
		item->set_service_type(service);
		item->set_monitor_key(it->first);
		item->set_monitor_value(it->second);
		item->set_timestamp(now);
	}

	std::string str_req;
	req.SerializeToString(&str_req);
	blink::MsgBody body;
	body.set_payload(str_req);
	body.set_service("monitor_data");
	body.set_method(1);
	body.set_call_type(blink::EN_MSG_TYPE_REQUEST);

	body.SerializeToString(&str_req);
	int rc = sendto(udp_fd, str_req.c_str(), str_req.size(), 0, dest_addr, addrlen);
	if(rc != (int)(str_req.size())){
		LOG_ERR("send to failed. fd:%d size:%llu rc:%d", udp_fd, str_req.size(), rc);
	}
	return 0;
}
