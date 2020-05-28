#include "pch.h"
#include "ProxyServer.h"
#include "AcceptorManager.h"
#include "SocketFactory.h"

void ltrim(std::string& str)
{
	if (str.empty())
		return;
	const char *itr = str.data(), *itrBegin = itr, *itrEnd = str.data() + str.size();
	for (; itr != itrEnd; ++itr)
		if (!isspace((uint8_t)*itr))
			break;
	str.erase(0, itr - itrBegin);
}

void rtrim(std::string& str)
{
	while (!str.empty() && isspace((uint8_t)str.back()))
		str.pop_back();
}

void trim(std::string& str)
{
	ltrim(str);
	rtrim(str);
}

class ConfigurableServer : public ProxyServer
{
public:
	ConfigurableServer(
		asio::io_context &ioCtx,
		const endpoint &ep,
		const ptree::ptree &upstreamAcceptorArgs,
		const ptree::ptree &upstreamUdpSocketArgs,
		const ptree::ptree &downstreamTcpSocketArgs,
		const ptree::ptree &downstreamAcceptorArgs,
		const ptree::ptree &downstreamUdpSocketArgs)
		:ProxyServer(ioCtx, ep), ioCtx_(ioCtx),
		upstreamAcceptorArgs_(upstreamAcceptorArgs),
		upstreamUdpSocketArgs_(upstreamUdpSocketArgs),
		downstreamTcpSocketArgs_(downstreamTcpSocketArgs),
		downstreamAcceptorArgs_(downstreamAcceptorArgs),
		downstreamUdpSocketArgs_(downstreamUdpSocketArgs)
	{
	}

	virtual std::unique_ptr<prx_listener> NewUpstreamAcceptor() override { return SocketFactory::LoadListener(upstreamAcceptorArgs_, ioCtx_); }
	virtual std::unique_ptr<prx_udp_socket> NewUpstreamUdpSocket() override { return SocketFactory::LoadUdpSocket(upstreamUdpSocketArgs_, ioCtx_); }
	virtual std::unique_ptr<prx_tcp_socket> NewDownstreamTcpSocket() override { return SocketFactory::LoadTcpSocket(downstreamTcpSocketArgs_, ioCtx_); }
	virtual std::unique_ptr<prx_listener> NewDownstreamAcceptor() override { return SocketFactory::LoadListener(downstreamAcceptorArgs_, ioCtx_); }
	virtual std::unique_ptr<prx_udp_socket> NewDownstreamUdpSocket() override { return SocketFactory::LoadUdpSocket(downstreamUdpSocketArgs_, ioCtx_); }
private:
	asio::io_context &ioCtx_;
	ptree::ptree upstreamAcceptorArgs_, upstreamUdpSocketArgs_, downstreamTcpSocketArgs_, downstreamAcceptorArgs_, downstreamUdpSocketArgs_;
};

void PrintPropertyTree(const ptree::ptree &node, int level = 0)
{
	for (const auto &val : node)
	{
		for (int i = 0; i < level; ++i)
			std::cout << ' ';
		std::cout << val.first << ": " << val.second.get_value("") << std::endl;
		if (!val.second.empty())
			PrintPropertyTree(val.second, level + 1);
	}
}

int main(int argc, char *argv[])
{
	std::string configPath;
	if (argc >= 2)
		configPath = argv[1];
	else
		configPath = "config.json";

	asio::io_context iosrv;
	asio::executor_work_guard<asio::io_context::executor_type> iosrv_work = boost::asio::make_work_guard(iosrv);
	std::thread th([&iosrv, &iosrv_work]() { while (iosrv_work.owns_work()) { try { iosrv.run(); } catch (std::exception &ex) { std::cerr << ex.what() << std::endl; } catch (...) {} }});
	th.detach();

	ptree::ptree root;
	ptree::read_json(configPath.c_str(), root);
	//PrintPropertyTree(root);

	std::unique_ptr<ProxyServer> server;
	server = std::make_unique<ConfigurableServer>(
		iosrv,
		SocketFactory::StringToEndpointWithResolve(root.get<std::string>("listen"), 1080, iosrv),
		root.get_child("upstreamAcceptor"),
		root.get_child("upstreamUdpSocket"),
		root.get_child("downstreamTcpSocket"),
		root.get_child("downstreamAcceptor"),
		root.get_child("downstreamUdpSocket")
		);
	server->Start();

	std::string cmd, arg;
	while (true)
	{
		std::getline(std::cin, cmd);
		arg.clear();

		trim(cmd);
		size_t pos = cmd.find(' ');
		if (pos != cmd.npos)
		{
			arg.assign(cmd, pos + 1);
			cmd.erase(pos);
		}

		if (cmd == "exit")
		{
			break;
		}
		else if (cmd == "list")
		{
			server->PrintSessions();
		}
	}

	server->Stop();
	AcceptorManager::Stop();
	iosrv_work.reset();
	while (!iosrv.stopped());

	return 0;
}
