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

#pragma once

#include "ServerConfigurationNode.h"

class ServerConfiguration
{
private:
	using NodeFactory = std::unordered_map<std::string, std::function<std::unique_ptr<ServerConfigurationNode>(const ptree::ptree &)>>;
public:
	ServerConfiguration(asio::io_context &io_context, const ptree::ptree &arg_root);

	endpoint UpstreamLocalEndpoint();
	std::unique_ptr<prx_udp_socket> NewUpstreamUdpSocket();
	std::unique_ptr<prx_listener> NewUpstreamListener();
	std::unique_ptr<prx_tcp_socket> NewDownstreamTcpSocket();
	std::unique_ptr<prx_udp_socket> NewDownstreamUdpSocket();
	std::unique_ptr<prx_listener> NewDownstreamListener();
private:
	ServerConfigurationNode *LoadRootNode(const ptree::ptree &args);
	ServerConfigurationNode *LoadTcpSocketNode(const ptree::ptree &args);
	ServerConfigurationNode *LoadUdpSocketNode(const ptree::ptree &args);
	ServerConfigurationNode *LoadListenerNode(const ptree::ptree &args);
	void AddNamedNode(const std::string &name, ServerConfigurationNode *node);

	endpoint StringToEndpoint(const std::string &str, port_type default_port);
	endpoint StringToEndpointWithResolve(const std::string &str, port_type default_port);

	asio::io_context &io_context_;
	std::vector<std::unique_ptr<ServerConfigurationNode>> nodes_;
	std::unordered_map<std::string, ServerConfigurationNode *> named_nodes_;
	NodeFactory tcp_socket_node_factories_, udp_socket_node_factories_, listener_node_factories_;
	ServerConfigurationNode *root_node_ = nullptr;
};
