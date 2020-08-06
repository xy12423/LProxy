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

class Socks4Session : public ProxySession
{
	static constexpr size_t kBufSize = 0x2000;

	static constexpr uint8_t kSocksVersion = 4, kReplyVersion = 0;
	static constexpr size_t kFixedHeaderSize = 8;
	enum
	{
		CONNECT = 1,
		BIND = 2
	};
public:
	Socks4Session(ProxyServer &server, std::unique_ptr<prx_tcp_socket> &&socket);
	virtual ~Socks4Session();

	virtual void Start() override;
	virtual void Start(char firstByte) override;
	virtual void Stop() override;
private:
	void ReceiveRequest();
	void ReceiveUsername(size_t upBufPBegin);
	void ReceiveDomain(size_t upBufPBegin);
	void DoRequest(uint8_t cmd, const endpoint &endpoint);

	void BeginConnect(const endpoint &endpoint);
	void EndConnect();
	void BeginBind(const endpoint &endpoint);
	void BeginBindAccept(const endpoint &endpoint);
	void EndBind(const endpoint &endpoint);
	void EndWithError();

	void ReceiveMore(null_callback &&complete_handler);
	void SendResponse(uint8_t err, const endpoint &ep, null_callback &&complete_handler);

	void RelayUpBuf();
	void RelayUp();
	void RelayDown();
	void ReadUpWhileAccept();

	std::unique_ptr<prx_tcp_socket> upTcp_;
	std::string username_;

	std::unique_ptr<prx_tcp_socket> downTcp_;
	AcceptorHandle downAcceptorHandle_;

	std::unique_ptr<char[]> upBuf_, downBuf_;
	size_t upBufP_ = 0, upBufPEnd_ = 0;

	std::atomic_bool replySent_{ false }, stopping_{ false };
};
