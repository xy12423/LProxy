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
#include "ServerConfigurationNodes.h"
#include "ServerConfigurationVisitor.h"

namespace
{

	struct md_sha256 : evp::md<md_sha256>
	{
		md_sha256() :md("SHA256") {}
	};

	uint8_t HexDigit(char ch)
	{
		switch (ch)
		{
		case '0':
			return 0;
		case '1':
			return 1;
		case '2':
			return 2;
		case '3':
			return 3;
		case '4':
			return 4;
		case '5':
			return 5;
		case '6':
			return 6;
		case '7':
			return 7;
		case '8':
			return 8;
		case '9':
			return 9;
		case 'A':
		case 'a':
			return 10;
		case 'B':
		case 'b':
			return 11;
		case 'C':
		case 'c':
			return 12;
		case 'D':
		case 'd':
			return 13;
		case 'E':
		case 'e':
			return 14;
		case 'F':
		case 'f':
			return 15;
		default:
			assert(false);
			return -1;
		}
	}

}

void ObjectReferenceNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

RawTcpSocketNode::RawTcpSocketNode(asio::io_context &io_context)
	:io_context_(io_context)
{
}

void RawTcpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_tcp_socket> RawTcpSocketNode::NewTcpSocket()
{
	return std::make_unique<raw_tcp_socket>(io_context_);
}

HttpTcpSocketNode::HttpTcpSocketNode(ServerConfigurationNode *base, const endpoint &server_endpoint)
	:LayeredTcpSocketNode(base),
	server_endpoint_(server_endpoint)
{
}

void HttpTcpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_tcp_socket> HttpTcpSocketNode::NewTcpSocket()
{
	return std::make_unique<http_tcp_socket>(Base().NewTcpSocket(), server_endpoint_);
}

Socks5TcpSocketNode::Socks5TcpSocketNode(ServerConfigurationNode *base, const endpoint &server_endpoint)
	:LayeredTcpSocketNode(base),
	server_endpoint_(server_endpoint)
{
}

void Socks5TcpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_tcp_socket> Socks5TcpSocketNode::NewTcpSocket()
{
	return std::make_unique<socks5_tcp_socket>(Base().NewTcpSocket(), server_endpoint_);
}

ObfsWebsockTcpSocketNode::ObfsWebsockTcpSocketNode(ServerConfigurationNode *base, const std::string &password)
	:LayeredTcpSocketNode(base)
{
	evp::message_digest<md_sha256> hasher;
	byte key_real[32];
	size_t key_real_size = sizeof(key_real);
	hasher.calculate_digest(key_real, key_real_size, (byte *)password.data(), password.size());
	if (key_real_size != sizeof(key_real))
		throw std::invalid_argument("Hash size mismatch");
	key_.resize(sizeof(key_real));
	memcpy(key_.data(), key_real, sizeof(key_real));
}

void ObfsWebsockTcpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_tcp_socket> ObfsWebsockTcpSocketNode::NewTcpSocket()
{
	return std::make_unique<obfs_websock_tcp_socket>(Base().NewTcpSocket(), key_);
}

WeightBasedSwitchTcpSocketNode::WeightBasedSwitchTcpSocketNode(Container &&base, Modes mode)
	:base_(std::move(base)), mode_(mode), itr_(base_.begin()), total_(0)
{
	if (base_.empty())
		throw std::invalid_argument("Need at least one base");
	for (const auto &p : base_)
	{
		if (p.weight < 0)
			throw std::invalid_argument("Weight must not be negative");
		total_ += p.weight;
	}
	if (total_ == 0)
		throw std::invalid_argument("Total weight must be more than 1");

	for (auto itr = base_.begin(), itr_end = base_.end(); itr != itr_end; ++itr)
		itr->acc = 0;
	itr_->acc = itr_->weight;
	while (itr_->acc < 1)
	{
		++itr_;
		if (itr_ == base_.end())
			itr_ = base_.begin();
		itr_->acc += itr_->weight;
	}
}

void WeightBasedSwitchTcpSocketNode::Validate() const
{
	for (const auto &p : base_)
		if (dynamic_cast<const TcpSocketNode *>(p.node) == nullptr)
			throw std::invalid_argument("Invalid base");
}

void WeightBasedSwitchTcpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_tcp_socket> WeightBasedSwitchTcpSocketNode::NewTcpSocket()
{
	switch (mode_)
	{
	case Modes::SEQUENTIAL:
	{
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		std::unique_ptr<prx_tcp_socket> socket = static_cast<TcpSocketNode *>(itr_->node)->NewTcpSocket();
		itr_->acc -= 1;
		while (itr_->acc < 1)
		{
			++itr_;
			if (itr_ == base_.end())
				itr_ = base_.begin();
			itr_->acc += itr_->weight;
		}
		return socket;
	}
	case Modes::RANDOM:
	{
		thread_local static std::default_random_engine generator(std::random_device{}());
		std::uniform_real_distribution<double> distribution(0, total_);
		double counter = distribution(generator);
		Iterator itr = base_.begin();
		while (counter >= itr->weight)
		{
			counter -= itr->weight;
			++itr;
			assert(itr_ != base_.end());
		}
		return static_cast<TcpSocketNode *>(itr->node)->NewTcpSocket();
	}
	default:
		assert(false);
		throw std::invalid_argument("Invalid mode");
	}
}

RawUdpSocketNode::RawUdpSocketNode(asio::io_context &io_context)
	:io_context_(io_context)
{
}

void RawUdpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_udp_socket> RawUdpSocketNode::NewUdpSocket()
{
	return std::make_unique<raw_udp_socket>(io_context_);
}

Socks5UdpSocketNode::Socks5UdpSocketNode(ServerConfigurationNode *base, const endpoint &server_endpoint)
	:base_(base), udp_base_(nullptr),
	server_endpoint_(server_endpoint)
{
}

Socks5UdpSocketNode::Socks5UdpSocketNode(ServerConfigurationNode *base, ServerConfigurationNode *udp_base, const endpoint &server_endpoint)
	:base_(base), udp_base_(udp_base),
	server_endpoint_(server_endpoint)
{
}

void Socks5UdpSocketNode::Validate() const
{
	if (dynamic_cast<const TcpSocketNode *>(base_) == nullptr)
		throw std::invalid_argument("Invalid base for base of Socks5UdpSocket");
	if (dynamic_cast<const UdpSocketNode *>(udp_base_) == nullptr)
		throw std::invalid_argument("Invalid base for udp base of Socks5UdpSocket");
}

void Socks5UdpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_udp_socket> Socks5UdpSocketNode::NewUdpSocket()
{
	return std::make_unique<socks5_udp_socket>(static_cast<TcpSocketNode *>(base_)->NewTcpSocket(), static_cast<UdpSocketNode *>(udp_base_)->NewUdpSocket(), server_endpoint_);
}

RawListenerNode::RawListenerNode(asio::io_context &io_context)
	:io_context_(io_context)
{
}

void RawListenerNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_listener> RawListenerNode::NewListener()
{
	return std::make_unique<raw_listener>(io_context_);
}

Socks5ListenerNode::Socks5ListenerNode(ServerConfigurationNode *base, const endpoint &server_endpoint)
	:LayeredNodeTemplate(base),
	server_endpoint_(server_endpoint)
{
}

void Socks5ListenerNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_listener> Socks5ListenerNode::NewListener()
{
	return std::make_unique<socks5_listener>([this]() { return Base().NewTcpSocket(); }, server_endpoint_);
}

ObfsWebsockListenerNode::ObfsWebsockListenerNode(ServerConfigurationNode *base, const std::string &password)
	:LayeredListenerNode(base)
{
	evp::message_digest<md_sha256> hasher;
	byte key_real[32];
	size_t key_real_size = sizeof(key_real);
	hasher.calculate_digest(key_real, key_real_size, (byte *)password.data(), password.size());
	if (key_real_size != sizeof(key_real))
		throw std::invalid_argument("Hash size mismatch");
	key_.resize(sizeof(key_real));
	memcpy(key_.data(), key_real, sizeof(key_real));
}

void ObfsWebsockListenerNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_listener> ObfsWebsockListenerNode::NewListener()
{
	return std::make_unique<obfs_websock_listener>(Base().NewListener(), key_);
}

RootNode::RootNode(
	int thread_count,
	int parallel_accept,
	const endpoint &upstream_local_endpoint,
	ServerConfigurationNode *upstream_listener,
	ServerConfigurationNode *upstream_udp_socket,
	ServerConfigurationNode *downstream_tcp_socket,
	ServerConfigurationNode *downstream_udp_socket,
	ServerConfigurationNode *downstream_listener
)
	:thread_count_(thread_count), parallel_accept_(parallel_accept),
	upstream_local_endpoint_(upstream_local_endpoint),
	downstream_tcp_socket_(downstream_tcp_socket),
	upstream_udp_socket_(upstream_udp_socket),
	downstream_udp_socket_(downstream_udp_socket),
	upstream_listener_(upstream_listener),
	downstream_listener_(downstream_listener)
{
}

void RootNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

void RootNode::Validate() const
{
	if (thread_count_ < 1 || thread_count_ > 16)
		throw std::invalid_argument("Invalid thread count");
	if (dynamic_cast<const TcpSocketNode *>(downstream_tcp_socket_) == nullptr)
		throw std::invalid_argument("Invalid downstream tcp socket");
	if (dynamic_cast<const UdpSocketNode *>(upstream_udp_socket_) == nullptr)
		throw std::invalid_argument("Invalid upstream udp socket");
	if (dynamic_cast<const UdpSocketNode *>(downstream_udp_socket_) == nullptr)
		throw std::invalid_argument("Invalid downstream udp socket");
	if (dynamic_cast<const ListenerNode *>(upstream_listener_) == nullptr)
		throw std::invalid_argument("Invalid upstream listener");
	if (dynamic_cast<const ListenerNode *>(downstream_listener_) == nullptr)
		throw std::invalid_argument("Invalid downstream listener");
}
