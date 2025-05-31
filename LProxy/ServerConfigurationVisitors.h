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

class NameResolvingVisitor : public ServerConfigurationVisitor
{
public:
	NameResolvingVisitor(const std::unordered_map<std::string, ServerConfigurationNode *> &named_nodes) :named_nodes_(named_nodes) {}

	virtual void Visit(ObjectReferenceNode &node) override;

	virtual void Visit(RawTcpSocketNode &node) override;
	virtual void Visit(HttpTcpSocketNode &node) override;
	virtual void Visit(Socks5TcpSocketNode &node) override;
	virtual void Visit(ObfsWebsockTcpSocketNode &node) override;
	virtual void Visit(WeightBasedSwitchTcpSocketNode &node) override;

	virtual void Visit(RawUdpSocketNode &node) override;
	virtual void Visit(Socks5UdpSocketNode &node) override;

	virtual void Visit(RawListenerNode &node) override;
	virtual void Visit(Socks5ListenerNode &node) override;
	virtual void Visit(ObfsWebsockListenerNode &node) override;

	virtual void Visit(SocksServiceNode &node) override;
	virtual void Visit(PortForwardServiceNode &node) override;

	virtual void Visit(ServiceListNode &node) override;
	virtual void Visit(RootNode &node) override;
private:
	const std::unordered_map<std::string, ServerConfigurationNode *> &named_nodes_;
	ServerConfigurationNode *return_value_ = nullptr;
};

class ValidatingVisitor : public ServerConfigurationVisitor
{
public:
	virtual void Visit(ObjectReferenceNode &node) override;

	virtual void Visit(RawTcpSocketNode &node) override;
	virtual void Visit(HttpTcpSocketNode &node) override;
	virtual void Visit(Socks5TcpSocketNode &node) override;
	virtual void Visit(ObfsWebsockTcpSocketNode &node) override;
	virtual void Visit(WeightBasedSwitchTcpSocketNode &node) override;

	virtual void Visit(RawUdpSocketNode &node) override;
	virtual void Visit(Socks5UdpSocketNode &node) override;

	virtual void Visit(RawListenerNode &node) override;
	virtual void Visit(Socks5ListenerNode &node) override;
	virtual void Visit(ObfsWebsockListenerNode &node) override;

	virtual void Visit(SocksServiceNode &node) override;
	virtual void Visit(PortForwardServiceNode &node) override;

	virtual void Visit(ServiceListNode &node) override;
	virtual void Visit(RootNode &node) override;
};
