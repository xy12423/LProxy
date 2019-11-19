#pragma once

class ProxySession;

class ProxyServer
{
	//Service management
public:
	ProxyServer(asio::io_context &ioContext, const endpoint &acceptorLocalEp);
	~ProxyServer();

	void Start();
	void Stop();

	void BeginSession(ProxySession *sessPtr, std::weak_ptr<ProxySession> &&sessWeak);
	void EndSession(ProxySession *sess);

	virtual prx_listener_base *NewUpstreamAcceptor() = 0;
	virtual prx_udp_socket_base *NewUpstreamUdpSocket() = 0;
	virtual prx_tcp_socket_base *NewDownstreamTcpSocket() = 0;
	virtual prx_listener_base *NewDownstreamAcceptor() = 0;
	virtual prx_udp_socket_base *NewDownstreamUdpSocket() = 0;
private:
	void Accept();
	void InitAcceptor();
	void InitAcceptorFailed();

	asio::io_context &ioContext_;
	std::unique_ptr<prx_listener_base> acceptor_;
	endpoint acceptorLocalEp_;
	boost::asio::steady_timer acceptorRetryTimer_;
	std::atomic_bool acceptorRetrying_ = false;
	std::unordered_map<ProxySession *, std::weak_ptr<ProxySession>> sessions_;
	std::recursive_mutex sessionsMutex_, acceptorMutex_;

	std::atomic_bool stopping_ = false;
};
