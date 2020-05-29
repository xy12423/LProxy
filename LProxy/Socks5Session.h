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

#include "ProxySession.h"
#include "AcceptorManager.h"

class Socks5Session : public ProxySession
{
	static constexpr size_t kBufSize = 0x10000;

	static constexpr uint8_t kSocksVersion = 5;
	enum
	{
		CONNECT = 1,
		BIND = 2,
		UDP_ASSOCIATE = 3,
		UDP_ASSOCIATE_OVER_TCP = 4,
	};
public:
	Socks5Session(ProxyServer &server, std::unique_ptr<prx_tcp_socket> &&socket);
	virtual ~Socks5Session();

	virtual void Start() override;
	virtual void Start(char firstByte) override;
	virtual void Stop() override;
private:
	void ReceiveHeader();
	void ReceiveHeaderWithFirstByte(char firstByte);
	void ReceiveMethodRequested();
	void SendMethodSelected();

	void ReceiveRequest();
	void BeginConnect(const endpoint &endpoint);
	void EndConnect();
	void BeginBind(const endpoint &endpoint);
	void BeginBindAccept();
	void EndBind();
	void BeginUdpAssociation(const endpoint &endpoint);
	void BeginUdpAssociationWithOpen(const endpoint &endpoint);
	void BeginUdpAssociationWithBind(const endpoint &endpoint);
	void EndUdpAssociation();
	void EndWithError(error_code errCode);

	void SendSocks5(uint8_t type, const endpoint &ep, null_callback &&complete_handler);
	void ReceiveSocks5(socksreq_callback &&complete_handler);
	void ReceiveSocks5Body(const std::shared_ptr<socksreq_callback> &callback);

	void RelayUp();
	void RelayDown();
	void ReadUpWhileAccept();
	void ReadUpKeepalive();
	void RelayUpUdpOverTcp();
	void RelayUpUdp();
	void RelayDownUdp();

	static error_code ParseUdp(const char *recv, size_t recvSize, endpoint &ep, const char *&dataStartAt, size_t &dataSize);

	static uint8_t SelectMethod(int argc, const uint8_t* argv);
	bool IsAdvancedProtocol();

	std::unique_ptr<prx_tcp_socket> upTcp_;
	uint8_t selectedMethod = 0xFF;

	std::unique_ptr<prx_tcp_socket> downTcp_;
	AcceptorHandle downAcceptorHandle_;
	std::unique_ptr<prx_udp_socket> upUdp_, downUdp_;
	endpoint upUdpRemoteEp_, upUdpFrom_, downUdpFrom_;

	std::unique_ptr<char[]> upBuf_, downBuf_, udpOverTcpBuf_;
	char udpKeepAliveBuf_;
	bool udpOverTcp_ = false;

	std::atomic_bool replySent_{ false }, stopping_{ false };
};
