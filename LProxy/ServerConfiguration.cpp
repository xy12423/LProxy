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
#include "ServerConfiguration.h"
#include "ServerConfigurationNodes.h"
#include "ServerConfigurationVisitors.h"

endpoint ServerConfiguration::StringToEndpoint(const std::string &str, port_type default_port)
{
	size_t pos_addr_begin = str.find_first_of('[');
	if (pos_addr_begin != std::string::npos)
	{
		pos_addr_begin = pos_addr_begin + 1;
		size_t pos_addr_end = str.find_first_of(']', pos_addr_begin);
		if (pos_addr_end == std::string::npos)
			throw std::runtime_error("Invalid string for endpoint");
		size_t pos_port_begin = str.find_first_of(':', pos_addr_end + 1);
		if (pos_port_begin != std::string::npos)
			return endpoint(str.substr(pos_addr_begin, pos_addr_end - pos_addr_begin), (port_type)std::stoi(str.substr(pos_port_begin + 1)));
		else
			return endpoint(str.substr(pos_addr_begin, pos_addr_end - pos_addr_begin), default_port);
	}
	else
	{
		size_t pos_port_begin = str.find_first_of(':');
		if (pos_port_begin != std::string::npos)
			return endpoint(str.substr(0, pos_port_begin), (port_type)std::stoi(str.substr(pos_port_begin + 1)));
		else
			return endpoint(str, default_port);
	}
}

endpoint ServerConfiguration::StringToEndpointWithResolve(const std::string &str, port_type default_port)
{
	asio::ip::tcp::resolver resolver(io_context_);
	asio::ip::tcp::endpoint resolved_ep;

	size_t pos_addr_begin = str.find_first_of('[');
	if (pos_addr_begin != std::string::npos)
	{
		pos_addr_begin = pos_addr_begin + 1;
		size_t pos_addr_end = str.find_first_of(']', pos_addr_begin);
		if (pos_addr_end == std::string::npos)
			throw std::runtime_error("Invalid string for endpoint");
		size_t pos_port_begin = str.find_first_of(':', pos_addr_end + 1);
		if (pos_port_begin != std::string::npos)
			resolved_ep = resolver.resolve({ str.substr(pos_addr_begin, pos_addr_end - pos_addr_begin), str.substr(pos_port_begin + 1) })->endpoint();
		else
			resolved_ep = resolver.resolve({ str.substr(pos_addr_begin, pos_addr_end - pos_addr_begin), std::to_string(default_port) })->endpoint();
	}
	else
	{
		size_t pos_port_begin = str.find_last_of(':');
		if (pos_port_begin != std::string::npos)
			resolved_ep = resolver.resolve({ str.substr(0, pos_port_begin), str.substr(pos_port_begin + 1) })->endpoint();
		else
			resolved_ep = resolver.resolve({ str, std::to_string(default_port) })->endpoint();
	}

	const asio::ip::address &resolved_addr = resolved_ep.address();
	if (resolved_addr.is_v4())
		return endpoint(resolved_addr.to_v4().to_ulong(), resolved_ep.port());
	else if (resolved_addr.is_v6())
		return endpoint(address_v6(resolved_addr.to_v6().to_bytes().data()), resolved_ep.port());
	else
		return endpoint(resolved_addr.to_string(), resolved_ep.port());
}

ServerConfiguration::ServerConfiguration(asio::io_context &io_context, const ptree::ptree &arg_root)
	:io_context_(io_context),
	tcp_socket_node_factories_{
		{"ref", [this](const ptree::ptree &args)->std::unique_ptr<ServerConfigurationNode>
			{
				return std::make_unique<ObjectReferenceNode>(args.get<std::string>("name"));
			}
		},
		{"raw", [this](const ptree::ptree &args)->std::unique_ptr<ServerConfigurationNode>
			{
				return std::make_unique<RawTcpSocketNode>(io_context_);
			}
		},
		{"http", [this](const ptree::ptree &args)->std::unique_ptr<ServerConfigurationNode>
			{
				return std::make_unique<HttpTcpSocketNode>(
					LoadTcpSocketNode(args.get_child("parent")),
					StringToEndpoint(args.get<std::string>("server"), 8080)
					);
			}
		},
		{"socks5", [this](const ptree::ptree &args)->std::unique_ptr<ServerConfigurationNode>
			{
				return std::make_unique<Socks5TcpSocketNode>(
					LoadTcpSocketNode(args.get_child("parent")),
					StringToEndpoint(args.get<std::string>("server"), 1080)
					);
			}
		},
		{"obfs_websock", [this](const ptree::ptree &args)->std::unique_ptr<ServerConfigurationNode>
			{
				return std::make_unique<ObfsWebsockTcpSocketNode>(
					LoadTcpSocketNode(args.get_child("parent")),
					args.get<std::string>("key")
					);
			}
		},
		{"weight_switch", [this](const ptree::ptree &args)->std::unique_ptr<ServerConfigurationNode>
			{
				WeightBasedSwitchTcpSocketNode::Container parents;
				for (const auto &node : args.get_child("parents"))
				{
					const auto &parent = node.second;
					parents.push_back(WeightBasedSwitchTcpSocketNode::BaseItem{ parent.get<double>("weight"), LoadTcpSocketNode(parent.get_child("parent")) });
				}
				std::string mode_str = args.get<std::string>("mode", "sequential");
				WeightBasedSwitchTcpSocketNode::Modes mode;
				if (mode_str == "sequential")
					mode = WeightBasedSwitchTcpSocketNode::Modes::SEQUENTIAL;
				else if (mode_str == "random")
					mode = WeightBasedSwitchTcpSocketNode::Modes::RANDOM;
				else
					mode = WeightBasedSwitchTcpSocketNode::Modes::SEQUENTIAL;
				return std::make_unique<WeightBasedSwitchTcpSocketNode>(
					std::move(parents),
					mode
					);
			}
		},
	},
	udp_socket_node_factories_{
		{"ref", [this](const ptree::ptree &args)->std::unique_ptr<ServerConfigurationNode>
			{
				return std::make_unique<ObjectReferenceNode>(args.get<std::string>("name"));
			}
		},
		{"raw", [this](const ptree::ptree &args)->std::unique_ptr<ServerConfigurationNode>
			{
				return std::make_unique<RawUdpSocketNode>(io_context_);
			}
		},
		{"socks5", [this](const ptree::ptree &args)->std::unique_ptr<ServerConfigurationNode>
			{
				return std::make_unique<Socks5UdpSocketNode>(
					LoadTcpSocketNode(args.get_child("parent_tcp")),
					LoadUdpSocketNode(args.get_child("parent")),
					StringToEndpoint(args.get<std::string>("server"), 1080)
					);
			}
		},
	},
	listener_node_factories_{
		{"ref", [this](const ptree::ptree &args)->std::unique_ptr<ServerConfigurationNode>
			{
				return std::make_unique<ObjectReferenceNode>(args.get<std::string>("name"));
			}
		},
		{"raw", [this](const ptree::ptree &args)->std::unique_ptr<ServerConfigurationNode>
			{
				return std::make_unique<RawListenerNode>(io_context_);
			}
		},
		{"socks5", [this](const ptree::ptree &args)->std::unique_ptr<ServerConfigurationNode>
			{
				return std::make_unique<Socks5ListenerNode>(
					LoadTcpSocketNode(args.get_child("parent_tcp")),
					StringToEndpoint(args.get<std::string>("server"), 1080)
					);
			}
		},
		{"obfs_websock", [this](const ptree::ptree &args)->std::unique_ptr<ServerConfigurationNode>
			{
				return std::make_unique<ObfsWebsockListenerNode>(
					LoadListenerNode(args.get_child("parent")),
					args.get<std::string>("key")
					);
			}
		}
	},
	service_node_factories_{
		{"socks", [this](const ptree::ptree &args)->std::unique_ptr<ServerConfigurationNode>
			{
				return std::make_unique<SocksServiceNode>(StringToEndpointWithResolve(args.get<std::string>("listen"), 1080));
			}
		},
		{"port_forward", [this](const ptree::ptree &args)->std::unique_ptr<ServerConfigurationNode>
			{
				return std::make_unique<PortForwardingServiceNode>(StringToEndpoint(args.get<std::string>("upstream"), 0), StringToEndpoint(args.get<std::string>("downstream"), 0));
			}
		},
	}
{
	root_node_ = LoadRootNode(arg_root);
	NameResolvingVisitor name_visitor(named_nodes_);
	root_node_->AcceptVisitor(name_visitor);
	ValidatingVisitor validating_visitor;
	root_node_->AcceptVisitor(validating_visitor);
}

int ServerConfiguration::Workers() const
{
	return static_cast<RootNode *>(root_node_)->ThreadCount();
}

int ServerConfiguration::ParallelAccept() const
{
	return static_cast<RootNode *>(root_node_)->ParallelAccept();
}

std::unique_ptr<prx_udp_socket> ServerConfiguration::NewUpstreamUdpSocket()
{
	return static_cast<UdpSocketNode *>(static_cast<RootNode *>(root_node_)->UpstreamUdpSocketNode())->NewUdpSocket();
}

std::unique_ptr<prx_listener> ServerConfiguration::NewUpstreamListener()
{
	return static_cast<ListenerNode *>(static_cast<RootNode *>(root_node_)->UpstreamListenerNode())->NewListener();
}

std::unique_ptr<prx_tcp_socket> ServerConfiguration::NewDownstreamTcpSocket()
{
	return static_cast<TcpSocketNode *>(static_cast<RootNode *>(root_node_)->DownstreamTcpSocketNode())->NewTcpSocket();
}

std::unique_ptr<prx_udp_socket> ServerConfiguration::NewDownstreamUdpSocket()
{
	return static_cast<UdpSocketNode *>(static_cast<RootNode *>(root_node_)->DownstreamUdpSocketNode())->NewUdpSocket();
}

std::unique_ptr<prx_listener> ServerConfiguration::NewDownstreamListener()
{
	return static_cast<ListenerNode *>(static_cast<RootNode *>(root_node_)->DownstreamListenerNode())->NewListener();
}

void ServerConfiguration::VisitAllServices(ServerConfigurationVisitor &visitor)
{
	for (ServerConfigurationNode *service : *static_cast<ServiceListNode *>(static_cast<RootNode *>(root_node_)->ServicesNode()))
	{
		service->AcceptVisitor(visitor);
	}
}

ServerConfigurationNode *ServerConfiguration::LoadRootNode(const ptree::ptree &args)
{
	std::unique_ptr<RootNode> node = std::make_unique<RootNode>(
		args.get<int>("workers", 1),
		args.get<int>("parallelAccept", 1),
		LoadListenerNode(args.get_child("upstreamAcceptor")),
		LoadUdpSocketNode(args.get_child("upstreamUdpSocket")),
		LoadTcpSocketNode(args.get_child("downstreamTcpSocket")),
		LoadUdpSocketNode(args.get_child("downstreamUdpSocket")),
		LoadListenerNode(args.get_child("downstreamAcceptor")),
		LoadServiceNodes(args.get_child("services", ptree::ptree()))
		);
	ServerConfigurationNode *ptr = node.get();
	nodes_.push_back(std::move(node));
	return ptr;
}

ServerConfigurationNode *ServerConfiguration::LoadTcpSocketNode(const ptree::ptree &args)
{
	std::unique_ptr<ServerConfigurationNode> node;
	try
	{
		node = tcp_socket_node_factories_.at(args.get<std::string>("type"))(args);
	}
	catch (const std::out_of_range &)
	{
		throw std::invalid_argument("Invalid tcp socket type " + args.get<std::string>("type"));
	}
	ServerConfigurationNode *node_ptr = node.get();
	nodes_.push_back(std::move(node));
	if (args.count("id") > 0)
		AddNamedNode(args.get<std::string>("id"), node_ptr);
	return node_ptr;
}

ServerConfigurationNode *ServerConfiguration::LoadUdpSocketNode(const ptree::ptree &args)
{
	std::unique_ptr<ServerConfigurationNode> node;
	try
	{
		node = udp_socket_node_factories_.at(args.get<std::string>("type"))(args);
	}
	catch (const std::out_of_range &)
	{
		throw std::invalid_argument("Invalid udp socket type " + args.get<std::string>("type"));
	}
	ServerConfigurationNode *node_ptr = node.get();
	nodes_.push_back(std::move(node));
	if (args.count("id") > 0)
		AddNamedNode(args.get<std::string>("id"), node_ptr);
	return node_ptr;
}

ServerConfigurationNode *ServerConfiguration::LoadListenerNode(const ptree::ptree &args)
{
	std::unique_ptr<ServerConfigurationNode> node;
	try
	{
		node = listener_node_factories_.at(args.get<std::string>("type"))(args);
	}
	catch (const std::out_of_range &)
	{
		throw std::invalid_argument("Invalid listener type " + args.get<std::string>("type"));
	}
	ServerConfigurationNode *node_ptr = node.get();
	nodes_.push_back(std::move(node));
	if (args.count("id") > 0)
		AddNamedNode(args.get<std::string>("id"), node_ptr);
	return node_ptr;
}

ServerConfigurationNode *ServerConfiguration::LoadServiceNode(const ptree::ptree &args)
{
	std::unique_ptr<ServerConfigurationNode> node;
	try
	{
		node = service_node_factories_.at(args.get<std::string>("type"))(args);
	}
	catch (const std::out_of_range &)
	{
		throw std::invalid_argument("Invalid service type " + args.get<std::string>("type"));
	}
	ServerConfigurationNode *node_ptr = node.get();
	nodes_.push_back(std::move(node));
	return node_ptr;
}

ServerConfigurationNode *ServerConfiguration::LoadServiceNodes(const ptree::ptree &args)
{
	std::unique_ptr<ServerConfigurationNode> node;
	try
	{
		ServiceListNode::Container services;
		for (const auto &node : args)
		{
			services.push_back(LoadServiceNode(node.second));
		}
		node = std::make_unique<ServiceListNode>(std::move(services));
	}
	catch (const std::exception &)
	{
		throw std::invalid_argument("Error while parsing service list");
	}
	ServerConfigurationNode *node_ptr = node.get();
	nodes_.push_back(std::move(node));
	return node_ptr;
}

void ServerConfiguration::AddNamedNode(const std::string &name, ServerConfigurationNode *node)
{
	if (named_nodes_.count(name) > 0)
		throw std::invalid_argument("Duplicate id of object");
	named_nodes_.emplace(name, node);
}
