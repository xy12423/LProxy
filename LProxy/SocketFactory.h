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

class SocketFactory
{
public:
	static endpoint StringToEndpoint(const std::string &str, port_type default_port);
	static endpoint StringToEndpointWithResolve(const std::string &str, port_type default_port, asio::io_context &ioContext);
	static std::unique_ptr<prx_tcp_socket> LoadTcpSocket(const ptree::ptree &args, asio::io_context &ioContext);
	static std::unique_ptr<prx_udp_socket> LoadUdpSocket(const ptree::ptree &args, asio::io_context &ioContext);
	static std::unique_ptr<prx_listener> LoadListener(const ptree::ptree &args, asio::io_context &ioContext);
};
