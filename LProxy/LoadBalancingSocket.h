#pragma once

class LoadBalancingSocketManager;

class LoadBalancingSocket final : prx_tcp_socket
{
public:
	LoadBalancingSocket();
};

class LoadBalancingListener final : prx_listener
{

};
