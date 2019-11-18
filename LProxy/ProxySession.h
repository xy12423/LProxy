#pragma once

class ProxyServer;

class ProxySession : public std::enable_shared_from_this<ProxySession>
{
public:
	ProxySession(ProxyServer &server);
	ProxySession(const ProxySession &) = delete;
	ProxySession(ProxySession &&) = delete;
	virtual ~ProxySession();

	virtual void Start() = 0;
	virtual void Stop() = 0;

	virtual void PrintInfo(std::ostream &out) = 0;
protected:
	ProxyServer &server_;
};
