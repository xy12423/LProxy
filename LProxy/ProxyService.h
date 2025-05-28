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

class ProxyServer;

class ProxyService
{
public:
	ProxyService(ProxyServer &server, asio::io_context &ioContext, const endpoint &acceptorLocalEp);
	virtual ~ProxyService() = default;

	void Start();
	void Stop();
protected:
	void StartAccept();
	void Accept(const std::shared_ptr<prx_listener> &acceptor, uint32_t acceptorID);
	virtual void StartSession(std::unique_ptr<prx_tcp_socket> &&acceptedSocket) = 0;
	void InitAcceptor(uint32_t failedAcceptorID);
	void InitAcceptorFailed(uint32_t failedAcceptorID);

	ProxyServer &server_;
	asio::io_context &ioContext_;

	std::shared_ptr<prx_listener> acceptor_;
	uint32_t acceptorID_;
	endpoint acceptorLocalEp_;
	bool acceptorRetrying_ = false;
	boost::asio::steady_timer acceptorRetryTimer_;
	std::recursive_mutex acceptorMutex_;

	std::atomic_bool stopping_{ false };
};
