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
#include "ServerConfigurationVisitor.h"
#include "ServerConfigurationNodes.h"

void NameResolvingVisitor::Visit(ObjectReferenceNode &node)
{
	// Node should be visited by its direct parent so don't revisit return value
	try
	{
		return_value_ = named_nodes_.at(node.Name());
	}
	catch (const std::out_of_range &)
	{
		throw std::invalid_argument("Invalid object reference " + node.Name());
	}
}

void NameResolvingVisitor::Visit(RawTcpSocketNode &node)
{
	return_value_ = nullptr;
}

void NameResolvingVisitor::Visit(HttpTcpSocketNode &node)
{
	node.BaseNode()->AcceptVisitor(*this);
	if (return_value_ != nullptr)
		node.SetBaseNode(return_value_);
	return_value_ = nullptr;
}

void NameResolvingVisitor::Visit(Socks5TcpSocketNode &node)
{
	node.BaseNode()->AcceptVisitor(*this);
	if (return_value_ != nullptr)
		node.SetBaseNode(return_value_);
	return_value_ = nullptr;
}

void NameResolvingVisitor::Visit(ObfsWebsockTcpSocketNode &node)
{
	node.BaseNode()->AcceptVisitor(*this);
	if (return_value_ != nullptr)
		node.SetBaseNode(return_value_);
	return_value_ = nullptr;
}

void NameResolvingVisitor::Visit(SSTcpSocketNode &node)
{
	node.BaseNode()->AcceptVisitor(*this);
	if (return_value_ != nullptr)
		node.SetBaseNode(return_value_);
	return_value_ = nullptr;
}

void NameResolvingVisitor::Visit(SSCryptoTcpSocketNode &node)
{
	node.BaseNode()->AcceptVisitor(*this);
	if (return_value_ != nullptr)
		node.SetBaseNode(return_value_);
	return_value_ = nullptr;
}

void NameResolvingVisitor::Visit(SSRAuthAes128Sha1TcpSocketNode &node)
{
	node.BaseNode()->AcceptVisitor(*this);
	if (return_value_ != nullptr)
		node.SetBaseNode(return_value_);
	return_value_ = nullptr;
}

void NameResolvingVisitor::Visit(SSRHttpSimpleTcpSocketNode &node)
{
	node.BaseNode()->AcceptVisitor(*this);
	if (return_value_ != nullptr)
		node.SetBaseNode(return_value_);
	return_value_ = nullptr;
}

void NameResolvingVisitor::Visit(VMessTcpSocketNode &node)
{
	node.BaseNode()->AcceptVisitor(*this);
	if (return_value_ != nullptr)
		node.SetBaseNode(return_value_);
	return_value_ = nullptr;
}

void NameResolvingVisitor::Visit(WeightBasedSwitchTcpSocketNode &node)
{
	for (auto itr = node.Begin(), itr_end = node.End(); itr != itr_end; ++itr)
	{
		itr->node->AcceptVisitor(*this);
		if (return_value_ != nullptr)
			itr->node = return_value_;
	}
	return_value_ = nullptr;
}

void NameResolvingVisitor::Visit(RawUdpSocketNode &node)
{
	return_value_ = nullptr;
}

void NameResolvingVisitor::Visit(Socks5UdpSocketNode &node)
{
	node.BaseNode()->AcceptVisitor(*this);
	if (return_value_ != nullptr)
		node.SetBaseNode(return_value_);
	if (node.UdpBaseNode() != nullptr)
	{
		node.UdpBaseNode()->AcceptVisitor(*this);
		if (return_value_ != nullptr)
			node.SetUdpBaseNode(return_value_);
	}
	return_value_ = nullptr;
}

void NameResolvingVisitor::Visit(SSUdpSocketNode &node)
{
	node.BaseNode()->AcceptVisitor(*this);
	if (return_value_ != nullptr)
		node.SetBaseNode(return_value_);
	return_value_ = nullptr;
}

void NameResolvingVisitor::Visit(SSCryptoUdpSocketNode &node)
{
	node.BaseNode()->AcceptVisitor(*this);
	if (return_value_ != nullptr)
		node.SetBaseNode(return_value_);
	return_value_ = nullptr;
}

void NameResolvingVisitor::Visit(RawListenerNode &node)
{
	return_value_ = nullptr;
}

void NameResolvingVisitor::Visit(Socks5ListenerNode &node)
{
	node.BaseNode()->AcceptVisitor(*this);
	if (return_value_ != nullptr)
		node.SetBaseNode(return_value_);
	return_value_ = nullptr;
}

void NameResolvingVisitor::Visit(ObfsWebsockListenerNode &node)
{
	node.BaseNode()->AcceptVisitor(*this);
	if (return_value_ != nullptr)
		node.SetBaseNode(return_value_);
	return_value_ = nullptr;
}

void NameResolvingVisitor::Visit(RootNode &node)
{
	node.DownstreamTcpSocketNode()->AcceptVisitor(*this);
	if (return_value_ != nullptr)
		node.SetDownstreamTcpSocketNode(return_value_);
	node.UpstreamUdpSocketNode()->AcceptVisitor(*this);
	if (return_value_ != nullptr)
		node.SetUpstreamUdpSocketNode(return_value_);
	node.DownstreamUdpSocketNode()->AcceptVisitor(*this);
	if (return_value_ != nullptr)
		node.SetDownstreamUdpSocketNode(return_value_);
	node.UpstreamListenerNode()->AcceptVisitor(*this);
	if (return_value_ != nullptr)
		node.SetUpstreamListenerNode(return_value_);
	node.DownstreamListenerNode()->AcceptVisitor(*this);
	if (return_value_ != nullptr)
		node.SetDownstreamListenerNode(return_value_);
	return_value_ = nullptr;
}

void ValidatingVisitor::Visit(ObjectReferenceNode &node)
{
}

void ValidatingVisitor::Visit(RawTcpSocketNode &node)
{
}

void ValidatingVisitor::Visit(HttpTcpSocketNode &node)
{
	node.Validate();
	node.BaseNode()->AcceptVisitor(*this);
}

void ValidatingVisitor::Visit(Socks5TcpSocketNode &node)
{
	node.Validate();
	node.BaseNode()->AcceptVisitor(*this);
}

void ValidatingVisitor::Visit(ObfsWebsockTcpSocketNode &node)
{
	node.Validate();
	node.BaseNode()->AcceptVisitor(*this);
}

void ValidatingVisitor::Visit(SSTcpSocketNode &node)
{
	node.Validate();
	node.BaseNode()->AcceptVisitor(*this);
}

void ValidatingVisitor::Visit(SSCryptoTcpSocketNode &node)
{
	node.Validate();
	node.BaseNode()->AcceptVisitor(*this);
}

void ValidatingVisitor::Visit(SSRAuthAes128Sha1TcpSocketNode &node)
{
	node.Validate();
	node.BaseNode()->AcceptVisitor(*this);
}

void ValidatingVisitor::Visit(SSRHttpSimpleTcpSocketNode &node)
{
	node.Validate();
	node.BaseNode()->AcceptVisitor(*this);
}

void ValidatingVisitor::Visit(VMessTcpSocketNode &node)
{
	node.Validate();
	node.BaseNode()->AcceptVisitor(*this);
}

void ValidatingVisitor::Visit(WeightBasedSwitchTcpSocketNode &node)
{
	node.Validate();
	for (auto itr = node.Begin(), itr_end = node.End(); itr != itr_end; ++itr)
		itr->node->AcceptVisitor(*this);
}

void ValidatingVisitor::Visit(RawUdpSocketNode &node)
{
}

void ValidatingVisitor::Visit(Socks5UdpSocketNode &node)
{
	node.Validate();
	node.BaseNode()->AcceptVisitor(*this);
	if (node.UdpBaseNode() != nullptr)
		node.UdpBaseNode()->AcceptVisitor(*this);
}

void ValidatingVisitor::Visit(SSUdpSocketNode &node)
{
	node.Validate();
	node.BaseNode()->AcceptVisitor(*this);
}

void ValidatingVisitor::Visit(SSCryptoUdpSocketNode &node)
{
	node.Validate();
	node.BaseNode()->AcceptVisitor(*this);
}

void ValidatingVisitor::Visit(RawListenerNode &node)
{
}

void ValidatingVisitor::Visit(Socks5ListenerNode &node)
{
	node.Validate();
	node.BaseNode()->AcceptVisitor(*this);
}

void ValidatingVisitor::Visit(ObfsWebsockListenerNode &node)
{
	node.Validate();
	node.BaseNode()->AcceptVisitor(*this);
}

void ValidatingVisitor::Visit(RootNode &node)
{
	node.Validate();
	node.DownstreamTcpSocketNode()->AcceptVisitor(*this);
	node.UpstreamUdpSocketNode()->AcceptVisitor(*this);
	node.DownstreamUdpSocketNode()->AcceptVisitor(*this);
	node.UpstreamListenerNode()->AcceptVisitor(*this);
	node.DownstreamListenerNode()->AcceptVisitor(*this);
}
