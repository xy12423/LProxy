#include "pch.h"
#include "ProxyServer.h"
#include "AcceptorManager.h"

std::string key;

class TestServer : public ProxyServer
{
public:
	TestServer(asio::io_context &ioCtx, const endpoint &ep) :ProxyServer(ioCtx, ep), ioCtx_(ioCtx) {}

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

	TestServer testServer(iosrv, endpoint(0ul, 12345));
	testServer.Start();

	std::cin.get();

	testServer.Stop();
	AcceptorManager::Stop();
	iosrv_work.reset();
	while (!iosrv.stopped());

	return 0;
}
