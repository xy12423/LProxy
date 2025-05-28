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
#include "SocksService.h"
#include "Socks4Session.h"
#include "Socks5Session.h"

void SocksService::StartSession(std::unique_ptr<prx_tcp_socket> &&acceptedSocket)
{
	prx_tcp_socket &socket = *acceptedSocket;
	std::shared_ptr<std::unique_ptr<prx_tcp_socket>> sharedSocketPtr = std::make_shared<std::unique_ptr<prx_tcp_socket>>(std::move(acceptedSocket));
	socket.async_recv([this, sharedSocketPtr = std::move(sharedSocketPtr)](error_code err, const_buffer data, buffer_data_store_holder &&dataHolder)
	{
		if (err)
			return;
		if (data.size() < 1)
			return;

		switch (data.data()[0])
		{
		case byte{ 4 }:
		{
			auto session = std::make_shared<Socks4Session>(server_, std::move(*sharedSocketPtr));
			session->Start(buffer_with_data_store{ data, std::move(dataHolder) });
			break;
		}
		case byte{ 5 }:
		{
			auto session = std::make_shared<Socks5Session>(server_, std::move(*sharedSocketPtr));
			session->Start(buffer_with_data_store{ data, std::move(dataHolder) });
			break;
		}
		}
	});
}
