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

#include "ProxyService.h"
#include "ProxySession.h"

class PortForwardSession : public ProxySession
{
public:
	PortForwardSession(ProxyServer &server, std::unique_ptr<prx_tcp_socket> &&socket, const endpoint &downstreamEp);
	virtual ~PortForwardSession();

	virtual void Start() override;
	virtual void Start(buffer_with_data_store &&leftover) override;
	virtual void Stop() override;
private:
	void BeginConnect();
	void RelayUpLeftover();
	void RelayUp();
	void RelayDown();

	endpoint downstreamEp_;

	std::unique_ptr<prx_tcp_socket> upTcp_;
	std::unique_ptr<prx_tcp_socket> downTcp_;
	buffer_with_data_store upLeftOver_, downLeftOver_;

	std::atomic_bool stopping_{ false };
};

class PortForwardService : public ProxyService
{
public:
	PortForwardService(ProxyServer &server, asio::io_context &ioContext, const endpoint &upstreamEp, const endpoint &downstreamEp) :ProxyService(server, ioContext, upstreamEp), downstreamEp_(downstreamEp) {}
protected:
	virtual void StartSession(std::unique_ptr<prx_tcp_socket> &&acceptedSocket) override;
private:
	endpoint downstreamEp_;
};
