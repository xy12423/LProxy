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
#include "ProxyServer.h"
#include "ProxyService.h"
#include "ProxySession.h"

std::recursive_mutex logMutex;

ProxyServer::ProxyServer(asio::io_context &ioContext)
	:ioContext_(ioContext)
{
}

ProxyServer::~ProxyServer()
{
}

void ProxyServer::Start()
{
	std::lock_guard<std::recursive_mutex> lock(serverMutex_);
	stopping_ = false;
	services_ = ConstructAllServices();
	for (const auto &service : services_)
		service->Start();
}

void ProxyServer::Stop()
{
	if (stopping_.exchange(true))
		return;
	std::lock_guard<std::recursive_mutex> lock(serverMutex_);
	for (const auto &service : services_)
		service->Stop();
	for (const auto &p : sessions_)
	{
		auto sess = p.second.lock();
		if (sess)
			sess->Stop();
	}
}

void ProxyServer::BeginSession(ProxySession *sessPtr, std::weak_ptr<ProxySession> &&sessWeak)
{
	std::lock_guard<std::recursive_mutex> lock(serverMutex_);
	if (stopping_)
		return;

	auto sess = sessWeak.lock();
	assert(&*sess == sessPtr);
	if (sess)
		sessions_[sessPtr] = sessWeak;
}

void ProxyServer::EndSession(ProxySession *sess)
{
	std::lock_guard<std::recursive_mutex> lock(serverMutex_);

	std::lock_guard<std::recursive_mutex> lock2(logMutex);
	std::cout << "End ";
	PrintSession(*sess);
	sessions_.erase(sess);
}

void ProxyServer::PrintSession(const ProxySession &sess)
{
	std::lock_guard<std::recursive_mutex> lock(logMutex);
	std::cout << sess.SessionType() << '\t';
	std::cout << sess.UpstreamEndpoint().addr().to_uri_string() << ':' << sess.UpstreamEndpoint().port() << '\t';
	std::cout << sess.DownstreamEndpoint().addr().to_uri_string() << ':' << sess.DownstreamEndpoint().port() << '\t';
	std::cout << sess.TotalBytesUp() << " Bytes up\t";
	std::cout << sess.TotalBytesDown() << " Bytes down" << std::endl;
}

void ProxyServer::PrintSessions()
{
	std::lock_guard<std::recursive_mutex> lock(serverMutex_);

	for (const auto &weakSession : sessions_)
		if (auto session = weakSession.second.lock())
			PrintSession(*session);
}
