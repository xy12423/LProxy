#pragma once

#include "ProxySession.h"

class Socks5Session : public ProxySession, public socks5_base
{
	static constexpr size_t kBufSize = 0x10000;
public:
	Socks5Session(ProxyServer &server, std::unique_ptr<prx_tcp_socket_base> &&socket);
	virtual ~Socks5Session();

	virtual void Start() override;
	virtual void Stop() override;

	virtual void PrintInfo(std::ostream &out) {}
private:
	void ReceiveRequest();
	void BeginConnect(const endpoint& endpoint);
	void EndConnect();
	void BeginBind(const endpoint& endpoint);
	void BeginBindAccept(const endpoint& endpoint);
	void EndBind();
	void BeginUdpAssociation(const endpoint& endpoint);
	void BeginUdpAssociationWithOpen(const endpoint& endpoint);
	void BeginUdpAssociationWithBind(const endpoint& endpoint);
	void EndUdpAssociation();
	void EndWithError(error_code errCode);

	void RelayUp();
	void RelayDown();

	void ReadUpWhileAccept();

	void ReadUpKeepalive();
	void RelayUpUdpOverTcp();
	void RelayUpUdp();
	void RelayDownUdp();

	std::unique_ptr<prx_tcp_socket_base> downTcp_;
	endpoint downAcceptorEp_;
	size_t downAcceptorId_ = 0;
	std::unique_ptr<prx_udp_socket_base> upUdp_, downUdp_;
	endpoint upUdpRemoteEp_, upUdpFrom_, downUdpFrom_;

	std::unique_ptr<char[]> upBuf_, downBuf_, udpOverTcpBuf_;
	char udpKeepAliveBuf_;

	std::atomic_bool replySent_ = false, stopping_ = false;
};
