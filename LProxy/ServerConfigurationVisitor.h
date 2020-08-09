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

class ServerConfigurationNode;

class ObjectReferenceNode;

class RawTcpSocketNode;
class HttpTcpSocketNode;
class Socks5TcpSocketNode;
class ObfsWebsockTcpSocketNode;
class SSTcpSocketNode;
class SSCryptoTcpSocketNode;
class SSRAuthAes128Sha1TcpSocketNode;
class SSRHttpSimpleTcpSocketNode;
class VMessTcpSocketNode;

class RawUdpSocketNode;
class Socks5UdpSocketNode;
class SSUdpSocketNode;
class SSCryptoUdpSocketNode;

class RawListenerNode;
class Socks5ListenerNode;
class ObfsWebsockListenerNode;
class RootNode;

class ServerConfigurationVisitor
{
public:
	virtual void Visit(ObjectReferenceNode &node) = 0;

	virtual void Visit(RawTcpSocketNode &node) = 0;
	virtual void Visit(HttpTcpSocketNode &node) = 0;
	virtual void Visit(Socks5TcpSocketNode &node) = 0;
	virtual void Visit(ObfsWebsockTcpSocketNode &node) = 0;
	virtual void Visit(SSTcpSocketNode &node) = 0;
	virtual void Visit(SSCryptoTcpSocketNode &node) = 0;
	virtual void Visit(SSRAuthAes128Sha1TcpSocketNode &node) = 0;
	virtual void Visit(SSRHttpSimpleTcpSocketNode &node) = 0;
	virtual void Visit(VMessTcpSocketNode &node) = 0;

	virtual void Visit(RawUdpSocketNode &node) = 0;
	virtual void Visit(Socks5UdpSocketNode &node) = 0;
	virtual void Visit(SSUdpSocketNode &node) = 0;
	virtual void Visit(SSCryptoUdpSocketNode &node) = 0;

	virtual void Visit(RawListenerNode &node) = 0;
	virtual void Visit(Socks5ListenerNode &node) = 0;
	virtual void Visit(ObfsWebsockListenerNode &node) = 0;
	virtual void Visit(RootNode &node) = 0;
};

class NameResolvingVisitor : public ServerConfigurationVisitor
{
public:
	NameResolvingVisitor(const std::unordered_map<std::string, ServerConfigurationNode *> &named_nodes) :named_nodes_(named_nodes) {}

	virtual void Visit(ObjectReferenceNode &node) override;

	virtual void Visit(RawTcpSocketNode &node) override;
	virtual void Visit(HttpTcpSocketNode &node) override;
	virtual void Visit(Socks5TcpSocketNode &node) override;
	virtual void Visit(ObfsWebsockTcpSocketNode &node) override;
	virtual void Visit(SSTcpSocketNode &node) override;
	virtual void Visit(SSCryptoTcpSocketNode &node) override;
	virtual void Visit(SSRAuthAes128Sha1TcpSocketNode &node) override;
	virtual void Visit(SSRHttpSimpleTcpSocketNode &node) override;
	virtual void Visit(VMessTcpSocketNode &node) override;

	virtual void Visit(RawUdpSocketNode &node) override;
	virtual void Visit(Socks5UdpSocketNode &node) override;
	virtual void Visit(SSUdpSocketNode &node) override;
	virtual void Visit(SSCryptoUdpSocketNode &node) override;

	virtual void Visit(RawListenerNode &node) override;
	virtual void Visit(Socks5ListenerNode &node) override;
	virtual void Visit(ObfsWebsockListenerNode &node) override;
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
	virtual void Visit(SSTcpSocketNode &node) override;
	virtual void Visit(SSCryptoTcpSocketNode &node) override;
	virtual void Visit(SSRAuthAes128Sha1TcpSocketNode &node) override;
	virtual void Visit(SSRHttpSimpleTcpSocketNode &node) override;
	virtual void Visit(VMessTcpSocketNode &node) override;

	virtual void Visit(RawUdpSocketNode &node) override;
	virtual void Visit(Socks5UdpSocketNode &node) override;
	virtual void Visit(SSUdpSocketNode &node) override;
	virtual void Visit(SSCryptoUdpSocketNode &node) override;

	virtual void Visit(RawListenerNode &node) override;
	virtual void Visit(Socks5ListenerNode &node) override;
	virtual void Visit(ObfsWebsockListenerNode &node) override;
	virtual void Visit(RootNode &node) override;
};
