#pragma once

class ProxySession;

class ProxyServer
{
	//Service management
public:
	ProxyServer(asio::io_context &ioContext, const endpoint &acceptorLocalEp);
	virtual ~ProxyServer();

	void Start();
	void Stop();

	void BeginSession(ProxySession *sessionPtr, std::weak_ptr<ProxySession> &&sessWeak);
	void EndSession(ProxySession *session);

	void PrintSession(const ProxySession &session);
	void PrintSessions();

	virtual std::unique_ptr<prx_listener> NewUpstreamAcceptor() = 0;
	virtual std::unique_ptr<prx_udp_socket> NewUpstreamUdpSocket() = 0;
	virtual std::unique_ptr<prx_tcp_socket> NewDownstreamTcpSocket() = 0;
	virtual std::unique_ptr<prx_listener> NewDownstreamAcceptor() = 0;
	virtual std::unique_ptr<prx_udp_socket> NewDownstreamUdpSocket() = 0;
private:
	void Accept();
	void InitAcceptor();
	void InitAcceptorFailed();

	asio::io_context &ioContext_;
	std::unique_ptr<prx_listener> acceptor_;
	endpoint acceptorLocalEp_;
	boost::asio::steady_timer acceptorRetryTimer_;
	std::atomic_bool acceptorRetrying_{ false };
	std::unordered_map<ProxySession *, std::weak_ptr<ProxySession>> sessions_;
	std::recursive_mutex sessionsMutex_, acceptorMutex_;

	std::atomic_bool stopping_{ false };
};
