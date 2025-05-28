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
#include "PortForwardService.h"
#include "ProxyServer.h"

PortForwardSession::PortForwardSession(ProxyServer &server, std::unique_ptr<prx_tcp_socket> &&socket, const endpoint &downstreamEp)
	:ProxySession(server), downstreamEp_(downstreamEp), upTcp_(std::move(socket))
{
	error_code err;
	upTcp_->remote_endpoint(AccessUpstreamEndpoint(), err);
	if (err)
		AccessUpstreamEndpoint() = endpoint();
	AccessSessionType() = "Forward";
}

PortForwardSession::~PortForwardSession()
{
	if (!stopping_)
		Stop();
}

void PortForwardSession::Start()
{
	auto self = shared_from_this();
	server_.BeginSession(this, std::weak_ptr<ProxySession>(self));

	BeginConnect();
}

void PortForwardSession::Start(buffer_with_data_store &&leftover)
{
	auto self = shared_from_this();
	server_.BeginSession(this, std::weak_ptr<ProxySession>(self));

	upLeftOver_ = std::move(leftover);
	BeginConnect();
}

void PortForwardSession::Stop()
{
	if (stopping_.exchange(true))
		return;

	error_code ec;
	if (upTcp_)
		upTcp_->close(ec);
	if (downTcp_)
		downTcp_->close(ec);
}

void PortForwardSession::BeginConnect()
{
	auto self = shared_from_this();

	downTcp_ = server_.NewDownstreamTcpSocket();
	downTcp_->async_open([this, self = std::move(self)](error_code err)
	{
		if (err)
		{
			Stop();
			return;
		}
		downTcp_->async_connect(downstreamEp_, [this, self](error_code err)
		{
			if (err)
			{
				Stop();
				return;
			}
			RelayUpLeftover();
			RelayDown();
		});
	});
}

void PortForwardSession::RelayUpLeftover()
{
	size_t transferred = upLeftOver_.buffer.size();
	if (transferred == 0)
	{
		RelayUp();
		return;
	}
	auto self = shared_from_this();
	downTcp_->async_send(upLeftOver_.buffer, std::move(upLeftOver_.holder),
		[this, self, transferred](error_code err)
	{
		if (err)
		{
			upTcp_->async_shutdown(prx_tcp_socket::shutdown_receive, [this, self](error_code) {});
			return;
		}
		AddBytesDown(transferred);
		RelayUp();
	});
}

void PortForwardSession::RelayUp()
{
	auto self = shared_from_this();
	upTcp_->async_recv([this, self = std::move(self)](error_code err, const_buffer data, buffer_data_store_holder &&dataHolder)
	{
		if (err)
		{
			downTcp_->async_shutdown(prx_tcp_socket::shutdown_send, [this, self](error_code) {});
			return;
		}
		size_t transferred = data.size();
		downTcp_->async_send(data, std::move(dataHolder),
			[this, self, transferred](error_code err)
		{
			if (err)
			{
				upTcp_->async_shutdown(prx_tcp_socket::shutdown_receive, [this, self](error_code) {});
				return;
			}
			AddBytesDown(transferred);
			RelayUp();
		});
	});
}

void PortForwardSession::RelayDown()
{
	auto self = shared_from_this();
	downTcp_->async_recv([this, self = std::move(self)](error_code err, const_buffer data, buffer_data_store_holder &&dataHolder)
	{
		if (err)
		{
			upTcp_->async_shutdown(prx_tcp_socket::shutdown_send, [this, self](error_code) {});
			return;
		}
		size_t transferred = data.size();
		upTcp_->async_send(data, std::move(dataHolder),
			[this, self, transferred](error_code err)
		{
			if (err)
			{
				downTcp_->async_shutdown(prx_tcp_socket::shutdown_receive, [this, self](error_code) {});
				return;
			}
			AddBytesUp(transferred);
			RelayDown();
		});
	});
}

void PortForwardService::StartSession(std::unique_ptr<prx_tcp_socket> &&acceptedSocket)
{
	auto session = std::make_shared<PortForwardSession>(server_, std::move(acceptedSocket), downstreamEp_);
	session->Start();
}
