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
#include "ProxyService.h"
#include "ProxyServer.h"

ProxyService::ProxyService(ProxyServer &server, asio::io_context &ioContext, const endpoint &acceptorLocalEp)
	:server_(server), ioContext_(ioContext),
	acceptorID_(0), acceptorLocalEp_(acceptorLocalEp), acceptorRetryTimer_(ioContext)
{
}

void ProxyService::Start()
{
	stopping_ = false;
	InitAcceptor(acceptorID_);
}

void ProxyService::Stop()
{
	if (stopping_.exchange(true))
		return;
	std::lock_guard<std::recursive_mutex> lockAcceptor(acceptorMutex_);

	boost::system::error_code ec;
	acceptorRetryTimer_.cancel(ec);
	error_code err;
	acceptor_->close(err);
}

void ProxyService::StartAccept()
{
	std::unique_lock<std::recursive_mutex> lock(acceptorMutex_);
	std::shared_ptr<prx_listener> acceptor = acceptor_;
	uint32_t acceptorID = acceptorID_;
	lock.unlock();
	for (int i = server_.ParallelAccept(); i > 0; --i)
	{
		Accept(acceptor, acceptorID);
	}
}

void ProxyService::Accept(const std::shared_ptr<prx_listener> &acceptor, uint32_t acceptorID)
{
	std::lock_guard<std::recursive_mutex> lock(acceptorMutex_);
	if (stopping_)
		return;

	if (!acceptor)
	{
		InitAcceptor(acceptorID);
		return;
	}
	acceptor->async_accept([this, acceptor, acceptorID](error_code err, std::unique_ptr<prx_tcp_socket> &&socketPtr)
	{
		if (err)
		{
			InitAcceptor(acceptorID);
			return;
		}

		StartSession(std::move(socketPtr));

		Accept(acceptor, acceptorID);
	});
}

void ProxyService::InitAcceptor(uint32_t failedAcceptorID)
{
	std::lock_guard<std::recursive_mutex> lock(acceptorMutex_);
	if (stopping_)
		return;
	if (failedAcceptorID != acceptorID_) // It's not current acceptor that's failed
		return;

	uint32_t newAcceptorID = ++acceptorID_;
	acceptor_ = server_.NewUpstreamAcceptor();
	acceptorRetrying_ = false;
	acceptor_->async_open([this, newAcceptorID](error_code err)
	{
		if (err)
		{
			InitAcceptorFailed(newAcceptorID);
			return;
		}
		acceptor_->async_bind(acceptorLocalEp_,
			[this, newAcceptorID](error_code err)
		{
			if (err)
			{
				InitAcceptorFailed(newAcceptorID);
				return;
			}
			acceptor_->async_listen([this, newAcceptorID](error_code err)
			{
				if (err)
				{
					InitAcceptorFailed(newAcceptorID);
					return;
				}
				StartAccept();
			});
		});
	});
}

void ProxyService::InitAcceptorFailed(uint32_t failedAcceptorID)
{
	std::lock_guard<std::recursive_mutex> lock(acceptorMutex_);
	if (stopping_)
		return;
	if (acceptorRetrying_)
		return;
	acceptorRetrying_ = true;

	acceptor_->async_close([this, failedAcceptorID](error_code)
	{
		std::lock_guard<std::recursive_mutex> lock(acceptorMutex_);
		if (stopping_)
			return;

		acceptorRetryTimer_.expires_after(std::chrono::seconds(5));
		acceptorRetryTimer_.async_wait([this, failedAcceptorID](const boost::system::error_code &ec)
		{
			if (!ec)
				InitAcceptor(failedAcceptorID);
		});
	});
}
