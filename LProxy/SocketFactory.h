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
