#include "pch.h"
#include "ProxyServer.h"
#include "AcceptorManager.h"

std::string key;

class EntranceServer : public ProxyServer
{
public:
	EntranceServer(asio::io_context &ioCtx, const endpoint &ep, const endpoint &exitEp) :ProxyServer(ioCtx, ep), ioCtx_(ioCtx), exitServerEp(exitEp) {}

	virtual prx_listener_base* NewUpstreamAcceptor() { return new raw_listener(ioCtx_); }
	virtual prx_udp_socket_base* NewUpstreamUdpSocket() { return new raw_udp_socket(ioCtx_); }
	virtual prx_tcp_socket_base* NewDownstreamTcpSocket() { return new socks5_tcp_socket(exitServerEp, std::make_unique<websock_tcp_socket>(std::make_unique<raw_tcp_socket>(ioCtx_), key)); }
	virtual prx_listener_base* NewDownstreamAcceptor() { return new socks5_listener(exitServerEp, [this]() { return std::make_unique<websock_tcp_socket>(std::make_unique<raw_tcp_socket>(ioCtx_), key); }); }
	virtual prx_udp_socket_base* NewDownstreamUdpSocket() { return new socks5_udp_socket(exitServerEp, std::make_unique<websock_tcp_socket>(std::make_unique<raw_tcp_socket>(ioCtx_), key)); }
private:
	asio::io_context &ioCtx_;
	endpoint exitServerEp;
};

class ExitServer : public ProxyServer
{
public:
	ExitServer(asio::io_context &ioCtx, const endpoint &ep) :ProxyServer(ioCtx, ep), ioCtx_(ioCtx) {}

	virtual prx_listener_base* NewUpstreamAcceptor() { return new websock_listener(std::make_unique<raw_listener>(ioCtx_), key); }
	virtual prx_udp_socket_base* NewUpstreamUdpSocket() { return new raw_udp_socket(ioCtx_); }
	virtual prx_tcp_socket_base* NewDownstreamTcpSocket() { return new raw_tcp_socket(ioCtx_); }
	virtual prx_listener_base* NewDownstreamAcceptor() { return new raw_listener(ioCtx_); }
	virtual prx_udp_socket_base* NewDownstreamUdpSocket() { return new raw_udp_socket(ioCtx_); }
private:
	asio::io_context &ioCtx_;
};

class ReverseExitServer : public ProxyServer
{
public:
	ReverseExitServer(asio::io_context &ioCtx, const endpoint &ep, const endpoint &remoteEp, const std::string &remoteKey) :ProxyServer(ioCtx, ep), ioCtx_(ioCtx), remoteEp_(remoteEp), remoteKey_(remoteKey) {}

	virtual prx_listener_base* NewUpstreamAcceptor() {
		return new websock_listener(
			std::make_unique<socks5_listener>(
				remoteEp_,
				[this]() { return std::make_unique<websock_tcp_socket>(std::make_unique<raw_tcp_socket>(ioCtx_), remoteKey_); }
				),
			key
		);
	}
	virtual prx_udp_socket_base* NewUpstreamUdpSocket() { return new raw_udp_socket(ioCtx_); }
	virtual prx_tcp_socket_base* NewDownstreamTcpSocket() { return new raw_tcp_socket(ioCtx_); }
	virtual prx_listener_base* NewDownstreamAcceptor() { return new raw_listener(ioCtx_); }
	virtual prx_udp_socket_base* NewDownstreamUdpSocket() { return new raw_udp_socket(ioCtx_); }
private:
	asio::io_context &ioCtx_;
	endpoint remoteEp_;
	std::string remoteKey_;
};

class RawServer : public ProxyServer
{
public:
	RawServer(asio::io_context &ioCtx, const endpoint &ep) :ProxyServer(ioCtx, ep), ioCtx_(ioCtx) {}

	virtual prx_listener_base* NewUpstreamAcceptor() { return new raw_listener(ioCtx_); }
	virtual prx_udp_socket_base* NewUpstreamUdpSocket() { return new raw_udp_socket(ioCtx_); }
	virtual prx_tcp_socket_base* NewDownstreamTcpSocket() { return new raw_tcp_socket(ioCtx_); }
	virtual prx_listener_base* NewDownstreamAcceptor() { return new raw_listener(ioCtx_); }
	virtual prx_udp_socket_base* NewDownstreamUdpSocket() { return new raw_udp_socket(ioCtx_); }
private:
	asio::io_context &ioCtx_;
};

int main(int argc, char *argv[])
{
	std::unordered_map<std::string, std::string> config_items;

	for (int i = 1; i < argc; i++)
	{
		std::string arg(argv[i]);
		size_t pos = arg.find('=');
		if (pos == std::string::npos)
			config_items[std::move(arg)].clear();
		else
			config_items[arg.substr(0, pos)] = arg.substr(pos + 1);
	}

	CryptoPP::SHA256 hasher;
	CryptoPP::byte key_real[CryptoPP::SHA256::DIGESTSIZE];
	hasher.CalculateDigest(key_real, (CryptoPP::byte*)(config_items.at("key").data()), config_items.at("key").size());
	key.assign((const char*)key_real, sizeof(key_real));

	asio::io_context iosrv;
	asio::executor_work_guard<asio::io_context::executor_type> iosrv_work = boost::asio::make_work_guard(iosrv);
	std::thread th([&iosrv, &iosrv_work]() { while (iosrv_work.owns_work()) { try { iosrv.run(); } catch (std::exception &ex) { std::cerr << ex.what() << std::endl; } catch (...) {} }});
	th.detach();

	if (config_items.count("client") > 0)
	{
		EntranceServer server(
			iosrv,
			endpoint(0x7F000001, (port_type)std::stoi(config_items.at("client_port"))),
			endpoint(config_items.at("server_addr"), (port_type)std::stoi(config_items.at("server_port")))
			);
		server.Start();

		std::cin.get();

		server.Stop();
	}
	else if (config_items.count("server") > 0)
	{
		ExitServer server(
			iosrv,
			endpoint(0ul, (port_type)std::stoi(config_items.at("server_port")))
		);
		server.Start();

		std::cin.get();

		server.Stop();
	}
	else if (config_items.count("test") > 0)
	{
		RawServer server(
			iosrv,
			endpoint(0ul, (port_type)std::stoi(config_items.at("server_port")))
		);
		server.Start();

		std::cin.get();

		server.Stop();
	}
	else if (config_items.count("reverse") > 0)
	{
		ReverseExitServer server(
			iosrv,
			endpoint(endpoint(0ul, (port_type)std::stoi(config_items.at("client_port")))),
			endpoint(config_items.at("server_addr"), (port_type)std::stoi(config_items.at("server_port"))),
			key
		);
		server.Start();

		std::cin.get();

		server.Stop();
	}

	AcceptorManager::Stop();
	iosrv_work.reset();
	while (!iosrv.stopped());

	return 0;
}
