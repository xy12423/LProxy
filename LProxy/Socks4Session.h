#pragma once

#include "ProxySession.h"
#include "AcceptorManager.h"

class Socks4Session : public ProxySession
{
	static constexpr size_t kBufSize = 0x10000;

	static constexpr uint8_t kSocksVersion = 4, kReplyVersion = 0;
	static constexpr size_t kFixedHeaderSize = 8;
	enum
	{
		CONNECT = 1,
		BIND = 2
	};
public:
	Socks4Session(ProxyServer &server, std::unique_ptr<prx_tcp_socket_base> &&socket);
	virtual ~Socks4Session();

	virtual void Start() override;
	virtual void Stop() override;
private:
	void ReceiveRequest();
	void ReceiveUsername(size_t upBufPBegin);
	void ReceiveDomain(size_t upBufPBegin);
	void DoRequest(uint8_t cmd, const endpoint &endpoint);

	void BeginConnect(const endpoint &endpoint);
	void EndConnect();
	void BeginBind(const endpoint &endpoint);
	void BeginBindAccept(const endpoint &endpoint);
	void EndBind(const endpoint &endpoint);
	void EndWithError();

	void SendResponse(uint8_t err, const endpoint &ep, null_callback &&complete_handler);

	void RelayUp();
	void RelayDown();
	void ReadUpWhileAccept();

	std::unique_ptr<prx_tcp_socket_base> upTcp_;
	std::string username_;

	std::unique_ptr<prx_tcp_socket_base> downTcp_;
	AcceptorHandle downAcceptorHandle_;
	std::unique_ptr<char[]> upBuf_, downBuf_;
	size_t upBufP_ = 0, upBufPEnd_ = 0;

	std::atomic_bool replySent_ = false, stopping_ = false;
};
