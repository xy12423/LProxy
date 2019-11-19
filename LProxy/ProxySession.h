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

	const endpoint &UpstreamEndpoint() const { return upEp_; }
	const endpoint &DownstreamEndpoint() const { return downEp_; }
	const std::string &TypeInfo() const { return type_; }
protected:
	endpoint &AccessUpstreamEndpoint() { return upEp_; }
	endpoint &AccessDownstreamEndpoint() { return downEp_; }
	std::string &AccessTypeInfo() { return type_; }

	ProxyServer &server_;
private:
	endpoint upEp_, downEp_;
	std::string type_;
};
