#include "pch.h"
#include "ProxySession.h"
#include "ProxyServer.h"

ProxySession::ProxySession(ProxyServer &server)
	:server_(server)
{
}

ProxySession::~ProxySession()
{
	server_.EndSession(this);
}
