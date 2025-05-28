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

class ObjectReferenceNode;

class RawTcpSocketNode;
class HttpTcpSocketNode;
class Socks5TcpSocketNode;
class ObfsWebsockTcpSocketNode;
class WeightBasedSwitchTcpSocketNode;

class RawUdpSocketNode;
class Socks5UdpSocketNode;

class RawListenerNode;
class Socks5ListenerNode;
class ObfsWebsockListenerNode;

class SocksServiceNode;
class PortForwardingServiceNode;

class ServiceListNode;
class RootNode;

class ServerConfigurationVisitor
{
public:
	virtual void Visit(ObjectReferenceNode &node) = 0;

	virtual void Visit(RawTcpSocketNode &node) = 0;
	virtual void Visit(HttpTcpSocketNode &node) = 0;
	virtual void Visit(Socks5TcpSocketNode &node) = 0;
	virtual void Visit(ObfsWebsockTcpSocketNode &node) = 0;
	virtual void Visit(WeightBasedSwitchTcpSocketNode &node) = 0;

	virtual void Visit(RawUdpSocketNode &node) = 0;
	virtual void Visit(Socks5UdpSocketNode &node) = 0;

	virtual void Visit(RawListenerNode &node) = 0;
	virtual void Visit(Socks5ListenerNode &node) = 0;
	virtual void Visit(ObfsWebsockListenerNode &node) = 0;

	virtual void Visit(SocksServiceNode &node) = 0;
	virtual void Visit(PortForwardingServiceNode &node) = 0;

	virtual void Visit(ServiceListNode &node) = 0;
	virtual void Visit(RootNode &node) = 0;
};

class ServerConfigurationNode
{
public:
	virtual ~ServerConfigurationNode() = default;

	virtual void AcceptVisitor(ServerConfigurationVisitor &visitor) = 0;
};
