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

class ObjectReferenceNode : public ServerConfigurationNode
{
public:
	ObjectReferenceNode(const std::string &name) :name_(name) {}

	const std::string &Name() const { return name_; }

	virtual void AcceptVisitor(ServerConfigurationVisitor &visitor) override;
private:
	std::string name_;
};

template <typename NodeType, typename BaseNodeType = NodeType>
class LayeredNodeTemplate : public NodeType
{
public:
	LayeredNodeTemplate(ServerConfigurationNode *base_node) :base_node_(base_node) {}

	ServerConfigurationNode *BaseNode() { return base_node_; }
	void SetBaseNode(ServerConfigurationNode *base_node) { base_node_ = base_node; }

	void Validate() const
	{
		if (dynamic_cast<BaseNodeType *>(base_node_) == nullptr)
			throw std::invalid_argument("Invalid base");
	}
protected:
	BaseNodeType &Base() { return *static_cast<BaseNodeType *>(base_node_); }
private:
	ServerConfigurationNode *base_node_;
};

class TcpSocketNode : public ServerConfigurationNode
{
public:
	virtual std::unique_ptr<prx_tcp_socket> NewTcpSocket() = 0;
};

using LayeredTcpSocketNode = LayeredNodeTemplate<TcpSocketNode>;

class RawTcpSocketNode : public TcpSocketNode
{
public:
	RawTcpSocketNode(asio::io_context &io_context) :io_context_(io_context) {}

	virtual void AcceptVisitor(ServerConfigurationVisitor &visitor) override;
	virtual std::unique_ptr<prx_tcp_socket> NewTcpSocket() override;
private:
	asio::io_context &io_context_;
};

class HttpTcpSocketNode : public LayeredTcpSocketNode
{
public:
	HttpTcpSocketNode(ServerConfigurationNode *base, const endpoint &server_endpoint) :LayeredTcpSocketNode(base), server_endpoint_(server_endpoint) {}

	virtual void AcceptVisitor(ServerConfigurationVisitor &visitor) override;
	virtual std::unique_ptr<prx_tcp_socket> NewTcpSocket() override;
private:
	endpoint server_endpoint_;
};

class Socks5TcpSocketNode : public LayeredTcpSocketNode
{
public:
	Socks5TcpSocketNode(ServerConfigurationNode *base, const endpoint &server_endpoint) :LayeredTcpSocketNode(base), server_endpoint_(server_endpoint) {}

	virtual void AcceptVisitor(ServerConfigurationVisitor &visitor) override;
	virtual std::unique_ptr<prx_tcp_socket> NewTcpSocket() override;
private:
	endpoint server_endpoint_;
};

class ObfsWebsockTcpSocketNode : public LayeredTcpSocketNode
{
public:
	ObfsWebsockTcpSocketNode(ServerConfigurationNode *base, const std::string &password);

	virtual void AcceptVisitor(ServerConfigurationVisitor &visitor) override;
	virtual std::unique_ptr<prx_tcp_socket> NewTcpSocket() override;
private:
	std::string key_;
};

class SSTcpSocketNode : public LayeredTcpSocketNode
{
public:
	SSTcpSocketNode(ServerConfigurationNode *base, const endpoint &server_endpoint) :LayeredTcpSocketNode(base), server_endpoint_(server_endpoint) {}

	virtual void AcceptVisitor(ServerConfigurationVisitor &visitor) override;
	virtual std::unique_ptr<prx_tcp_socket> NewTcpSocket() override;
private:
	endpoint server_endpoint_;
};

class SSCryptoTcpSocketNode : public LayeredTcpSocketNode
{
public:
	SSCryptoTcpSocketNode(ServerConfigurationNode *base, const std::string &method, const std::string &password);

	std::unique_ptr<ss::ss_crypto_tcp_socket> NewSSCryptoTcpSocket();

	virtual void AcceptVisitor(ServerConfigurationVisitor &visitor) override;
	virtual std::unique_ptr<prx_tcp_socket> NewTcpSocket() override;
private:
	std::string method_;
	std::vector<char> key_;
};

class SSRAuthAes128Sha1TcpSocketNode : public LayeredNodeTemplate<TcpSocketNode, SSCryptoTcpSocketNode>
{
public:
	SSRAuthAes128Sha1TcpSocketNode(ServerConfigurationNode *base, const std::string &param)
		:LayeredNodeTemplate(base), param_(param)
	{
	}

	virtual void AcceptVisitor(ServerConfigurationVisitor &visitor) override;
	virtual std::unique_ptr<prx_tcp_socket> NewTcpSocket() override;
private:
	std::string param_;
};

class SSRHttpSimpleTcpSocketNode : public LayeredTcpSocketNode
{
public:
	SSRHttpSimpleTcpSocketNode(ServerConfigurationNode *base, const std::string &param)
		:LayeredTcpSocketNode(base), param_(param)
	{
	}

	virtual void AcceptVisitor(ServerConfigurationVisitor &visitor) override;
	virtual std::unique_ptr<prx_tcp_socket> NewTcpSocket() override;
private:
	std::string param_;
};

class UdpSocketNode : public ServerConfigurationNode
{
public:
	virtual std::unique_ptr<prx_udp_socket> NewUdpSocket() = 0;
};

using LayeredUdpSocketNode = LayeredNodeTemplate<UdpSocketNode>;

class RawUdpSocketNode : public UdpSocketNode
{
public:
	RawUdpSocketNode(asio::io_context &io_context) :io_context_(io_context) {}

	virtual void AcceptVisitor(ServerConfigurationVisitor &visitor) override;
	virtual std::unique_ptr<prx_udp_socket> NewUdpSocket() override;
private:
	asio::io_context &io_context_;
};

class Socks5UdpSocketNode : public UdpSocketNode
{
public:
	Socks5UdpSocketNode(ServerConfigurationNode *base, const endpoint &server_endpoint) :base_(base), udp_base_(nullptr), server_endpoint_(server_endpoint) {}
	Socks5UdpSocketNode(ServerConfigurationNode *base, ServerConfigurationNode *udp_base, const endpoint &server_endpoint) :base_(base), udp_base_(udp_base), server_endpoint_(server_endpoint) {}

	ServerConfigurationNode *BaseNode() { return base_; }
	void SetBaseNode(ServerConfigurationNode *base_node) { base_ = base_node; }
	ServerConfigurationNode *UdpBaseNode() { return udp_base_; }
	void SetUdpBaseNode(ServerConfigurationNode *udp_base_node) { udp_base_ = udp_base_node; }

	void Validate() const;

	virtual void AcceptVisitor(ServerConfigurationVisitor &visitor) override;
	virtual std::unique_ptr<prx_udp_socket> NewUdpSocket() override;
private:
	ServerConfigurationNode *base_;
	ServerConfigurationNode *udp_base_;
	endpoint server_endpoint_;
};

class SSUdpSocketNode : public LayeredUdpSocketNode
{
public:
	SSUdpSocketNode(ServerConfigurationNode *base, const endpoint &server_endpoint) :LayeredUdpSocketNode(base), server_endpoint_(server_endpoint) {}

	virtual void AcceptVisitor(ServerConfigurationVisitor &visitor) override;
	virtual std::unique_ptr<prx_udp_socket> NewUdpSocket() override { return std::make_unique<ss::ss_udp_socket>(Base().NewUdpSocket(), server_endpoint_); }
private:
	endpoint server_endpoint_;
};

class SSCryptoUdpSocketNode : public LayeredUdpSocketNode
{
public:
	SSCryptoUdpSocketNode(ServerConfigurationNode *base, const std::string &method, const std::string &password);

	std::unique_ptr<ss::ss_crypto_udp_socket> NewSSCryptoUdpSocket();

	virtual void AcceptVisitor(ServerConfigurationVisitor &visitor) override;
	virtual std::unique_ptr<prx_udp_socket> NewUdpSocket() override;
private:
	std::string method_;
	std::vector<char> key_;
};

class ListenerNode : public ServerConfigurationNode
{
public:
	virtual std::unique_ptr<prx_listener> NewListener() = 0;
};

using LayeredListenerNode = LayeredNodeTemplate<ListenerNode>;

class RawListenerNode : public ListenerNode
{
public:
	RawListenerNode(asio::io_context &io_context) :io_context_(io_context) {}

	virtual void AcceptVisitor(ServerConfigurationVisitor &visitor) override;
	virtual std::unique_ptr<prx_listener> NewListener() override;
private:
	asio::io_context &io_context_;
};

class Socks5ListenerNode : public LayeredNodeTemplate<ListenerNode, TcpSocketNode>
{
public:
	Socks5ListenerNode(ServerConfigurationNode *base, const endpoint &server_endpoint) :LayeredNodeTemplate(base), server_endpoint_(server_endpoint) {}

	virtual void AcceptVisitor(ServerConfigurationVisitor &visitor) override;
	virtual std::unique_ptr<prx_listener> NewListener() override;
private:
	endpoint server_endpoint_;
};

class ObfsWebsockListenerNode : public LayeredListenerNode
{
public:
	ObfsWebsockListenerNode(ServerConfigurationNode *base, const std::string &password);

	virtual void AcceptVisitor(ServerConfigurationVisitor &visitor) override;
	virtual std::unique_ptr<prx_listener> NewListener() override;
private:
	std::string key_;
};

class RootNode : public ServerConfigurationNode
{
public:
	RootNode(
		const endpoint &upstream_local_endpoint,
		ServerConfigurationNode *upstream_listener,
		ServerConfigurationNode *upstream_udp_socket,
		ServerConfigurationNode *downstream_tcp_socket,
		ServerConfigurationNode *downstream_udp_socket,
		ServerConfigurationNode *downstream_listener
	);

	virtual void AcceptVisitor(ServerConfigurationVisitor &visitor) override;

	const endpoint &UpstreamLocalEndpoint() const { return upstream_local_endpoint_; }

	ServerConfigurationNode *DownstreamTcpSocketNode() { return downstream_tcp_socket_; }
	void SetDownstreamTcpSocketNode(ServerConfigurationNode *value) { downstream_tcp_socket_ = value; }
	ServerConfigurationNode *UpstreamUdpSocketNode() { return upstream_udp_socket_; }
	void SetUpstreamUdpSocketNode(ServerConfigurationNode *value) { upstream_udp_socket_ = value; }
	ServerConfigurationNode *DownstreamUdpSocketNode() { return downstream_udp_socket_; }
	void SetDownstreamUdpSocketNode(ServerConfigurationNode *value) { downstream_udp_socket_ = value; }
	ServerConfigurationNode *UpstreamListenerNode() { return upstream_listener_; }
	void SetUpstreamListenerNode(ServerConfigurationNode *value) { upstream_listener_ = value; }
	ServerConfigurationNode *DownstreamListenerNode() { return downstream_listener_; }
	void SetDownstreamListenerNode(ServerConfigurationNode *value) { downstream_listener_ = value; }

	void Validate() const;
private:
	endpoint upstream_local_endpoint_;
	ServerConfigurationNode *downstream_tcp_socket_, *upstream_udp_socket_, *downstream_udp_socket_, *upstream_listener_, *downstream_listener_;
};
