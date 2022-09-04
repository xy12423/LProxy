/*
Copyright (c) 2020 xy12423

This file is part of LProxy.

LProxy is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

LProxy is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with LProxy. If not, see <https://www.gnu.org/licenses/>.
*/

#include "pch.h"
#include "ProxyServer.h"
#include "AcceptorManager.h"
#include "ServerConfiguration.h"

extern std::recursive_mutex logMutex;

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
		const std::shared_ptr<ServerConfiguration> &conf)
		:ProxyServer(ioCtx, conf->UpstreamLocalEndpoint()), ioCtx_(ioCtx), configuration_(conf)
	{
	}

	void SetConfiguration(const std::shared_ptr<ServerConfiguration> &conf) { configuration_ = conf; }

	virtual std::unique_ptr<prx_listener> NewUpstreamAcceptor() override
	{
		std::shared_ptr<ServerConfiguration> conf = configuration_;
		return conf->NewUpstreamListener();
	}
	virtual std::unique_ptr<prx_udp_socket> NewUpstreamUdpSocket() override
	{
		std::shared_ptr<ServerConfiguration> conf = configuration_;
		return conf->NewUpstreamUdpSocket();
	}
	virtual std::unique_ptr<prx_tcp_socket> NewDownstreamTcpSocket() override
	{
		std::shared_ptr<ServerConfiguration> conf = configuration_;
		return conf->NewDownstreamTcpSocket();
	}
	virtual std::unique_ptr<prx_listener> NewDownstreamAcceptor() override
	{
		std::shared_ptr<ServerConfiguration> conf = configuration_;
		return conf->NewDownstreamListener();
	}
	virtual std::unique_ptr<prx_udp_socket> NewDownstreamUdpSocket() override
	{
		std::shared_ptr<ServerConfiguration> conf = configuration_;
		return conf->NewDownstreamUdpSocket();
	}

	virtual int ParallelAccept() override
	{
		std::shared_ptr<ServerConfiguration> conf = configuration_;
		return conf->ParallelAccept();
	}
private:
	asio::io_context &ioCtx_;
	std::shared_ptr<ServerConfiguration> configuration_;
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
	auto worker_function = [&iosrv, &iosrv_work]()
	{
		while (iosrv_work.owns_work())
		{
			try
			{
				iosrv.run();
			}
			catch (std::exception &ex)
			{
				std::lock_guard<std::recursive_mutex> lock(logMutex);
				std::cerr << ex.what() << std::endl;
			}
			catch (...) {}
		}
	};
	std::vector<std::thread> worker_threads;
	worker_threads.emplace_back(worker_function); //First worker thread

	ptree::ptree root;
	ptree::read_json(configPath.c_str(), root);
	//PrintPropertyTree(root);

	std::shared_ptr<ServerConfiguration> conf;
	try
	{
		conf = std::make_shared<ServerConfiguration>(iosrv, root);
	}
	catch (const std::exception &e)
	{
		std::cerr << e.what() << std::endl;
		AcceptorManager::Stop();
		iosrv_work.reset();
		for (auto itr = worker_threads.begin(), itr_end = worker_threads.end(); itr != itr_end; ++itr)
			itr->join();
		return 1;
	}

	while (worker_threads.size() < (size_t)conf->Workers())
		worker_threads.emplace_back(worker_function); //Extra worker threads

	std::unique_ptr<ConfigurableServer> server;
	server = std::make_unique<ConfigurableServer>(iosrv, conf);
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
			ltrim(arg);
			rtrim(cmd);
		}

		if (cmd == "exit")
		{
			break;
		}
		else if (cmd == "list")
		{
			server->PrintSessions();
		}
		else if (cmd == "reload")
		{
			try
			{
				root.clear();
				if (!arg.empty())
					ptree::read_json(arg.c_str(), root);
				else
					ptree::read_json(configPath.c_str(), root);

				conf = std::make_shared<ServerConfiguration>(iosrv, root);
				server->SetConfiguration(conf);
			}
			catch (const std::exception &ex)
			{
				std::lock_guard<std::recursive_mutex> lock(logMutex);
				std::cerr << ex.what() << std::endl;
			}
		}
	}

	server->Stop();
	AcceptorManager::Stop();
	iosrv_work.reset();
	for (auto itr = worker_threads.begin(), itr_end = worker_threads.end(); itr != itr_end; ++itr)
		itr->join();

	return 0;
}
