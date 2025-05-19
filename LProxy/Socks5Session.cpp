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
#include "Socks5Session.h"
#include "ProxyServer.h"

static endpoint kEpZero((uint32_t)0, 0);

Socks5Session::Socks5Session(ProxyServer &server, std::unique_ptr<prx_tcp_socket> &&socket)
	:ProxySession(server), upTcp_(std::move(socket))
{
	error_code err;
	upTcp_->remote_endpoint(AccessUpstreamEndpoint(), err);
	if (err)
		AccessUpstreamEndpoint() = endpoint();
	AccessSessionType() = "Socks5";
}

Socks5Session::~Socks5Session()
{
	if (!stopping_)
		Stop();
}

void Socks5Session::Start()
{
	auto self = shared_from_this();
	server_.BeginSession(this, std::weak_ptr<ProxySession>(self));

	ReceiveHeader();
}

void Socks5Session::Start(buffer_with_data_store &&leftover)
{
	auto self = shared_from_this();
	server_.BeginSession(this, std::weak_ptr<ProxySession>(self));

	upLeftOver_ = std::move(leftover);
	ReceiveHeader();
}

void Socks5Session::Stop()
{
	if (stopping_.exchange(true))
		return;

	downAcceptorHandle_.CancelAccept();
	error_code ec;
	if (upTcp_)
		upTcp_->close(ec);
	if (downTcp_)
		downTcp_->close(ec);
	if (upUdp_)
		upUdp_->close(ec);
	if (downUdp_)
		downUdp_->close(ec);
}

void Socks5Session::ReceiveHeader()
{
	auto self = shared_from_this();

	selectedMethod = 0xFF;

	static_assert(kBufSize >= 257, "upBuf_ is too small");

	struct Header
	{
		//Max size of a valid header is 257
		byte buf[257];
		size_t bufSize = 0;
	};
	std::shared_ptr<Header> header = std::make_shared<Header>();

	upTcp_->async_recv_until(std::move(upLeftOver_),
		[this, self, header](const_buffer &data)
	{
		if (header->bufSize < 2)
		{
			header->bufSize += const_buffer::consume(header->buf + header->bufSize, 2 - header->bufSize, data);
			if (header->bufSize < 2)
				return error_code_or_op_result{ OPRESULT_CONTINUE };
			if (header->buf[0] != kSocksVersion)
				return error_code_or_op_result{ OPRESULT_ERROR };
		}
		size_t expected = 2 + std::to_integer<size_t>(header->buf[1]);
		if (expected > sizeof(Header::buf)) [[unlikely]]
		{
			return error_code_or_op_result{ OPRESULT_ERROR };
		}
		if (header->bufSize < expected)
		{
			header->bufSize += const_buffer::consume(header->buf + header->bufSize, expected - header->bufSize, data);
			if (header->bufSize < expected)
				return error_code_or_op_result{ OPRESULT_CONTINUE };
		}
		return error_code_or_op_result{ OPRESULT_COMPLETED };
	}, [this, self, header](error_code_or_op_result ec_or_result, buffer_with_data_store &&leftover)
	{
		if (ec_or_result.code == OPRESULT_ERROR) [[unlikely]]
		{
			Stop();
			return;
		}
		if (ec_or_result.code != OPRESULT_COMPLETED) [[unlikely]]
		{
			Stop();
			return;
		}
		upLeftOver_ = std::move(leftover);
		selectedMethod = SelectMethod(std::to_integer<uint8_t>(header->buf[1]), (uint8_t *)(header->buf + 2));
		SendMethodSelected();
	});
}

void Socks5Session::SendMethodSelected()
{
	auto self = shared_from_this();

	using SendMethodSelectedPayload = std::array<byte, 2>;
	PRXSOCKET_MAKE_INPLACE_BUFFER(SendMethodSelectedPayload, methodSelected, methodSelectedHolder);
	methodSelected[0] = kSocksVersion;
	methodSelected[1] = byte{ selectedMethod };
	upTcp_->async_send(const_buffer(methodSelected.data(), methodSelected.size()), std::move(methodSelectedHolder),
		[this, self = std::move(self), methodSelected](error_code err)
	{
		if (err)
		{
			Stop();
			return;
		}
		if (selectedMethod == 0xFF)
		{
			Stop();
			return;
		}
		ReceiveRequest();
	});
}

void Socks5Session::ReceiveRequest()
{
	auto self = shared_from_this();

	ReceiveSocks5([this, self = std::move(self)](error_code err, uint8_t cmd, const endpoint& ep)
	{
		if (err)
		{
			Stop();
			return;
		}
		AccessDownstreamEndpoint() = ep;
		switch (cmd)
		{
		case CONNECT:
			AccessSessionType().append(" Connect");
			BeginConnect(ep);
			break;
		case BIND:
			AccessSessionType().append(" Bind");
			if (IsAdvancedProtocol())
				AccessSessionType().append(" Advanced");
			BeginBind(ep);
			break;
		case UDP_ASSOCIATE:
			AccessSessionType().append(" Udp Associate");
			if (IsAdvancedProtocol())
				AccessSessionType().append(" Advanced");
			BeginUdpAssociation(ep);
			break;
		default:
			Stop();
			return;
		}

		server_.PrintSession(*this);
	});
}

void Socks5Session::BeginConnect(const endpoint &ep)
{
	auto self = shared_from_this();

	downTcp_ = server_.NewDownstreamTcpSocket();
	downTcp_->async_open([this, self = std::move(self), ep](error_code err)
	{
		if (err)
		{
			EndWithError(err);
			return;
		}
		downTcp_->async_connect(ep, [this, self](error_code err)
		{
			if (err)
			{
				EndWithError(err);
				return;
			}
			EndConnect();
		});
	});
}

void Socks5Session::EndConnect()
{
	auto self = shared_from_this();
	error_code err;

	endpoint downLocalEp;
	downTcp_->local_endpoint(downLocalEp, err);

	if (replySent_.exchange(true))
		return;
	SendSocks5(0, (err ? kEpZero : downLocalEp),
		[this, self = std::move(self)](error_code err)
	{
		if (err)
		{
			Stop();
			return;
		}
		RelayUpLeftover();
		RelayDown();
	});
}

void Socks5Session::BeginBind(const endpoint &ep)
{
	auto self = shared_from_this();

	endpoint downAcceptorRequestEp = (IsAdvancedProtocol() ? ep : kEpZero);
	downAcceptorHandle_.AsyncPrepare(downAcceptorRequestEp,
		[this]()->std::unique_ptr<prx_listener> { return std::unique_ptr<prx_listener>(server_.NewDownstreamAcceptor()); },
		[this, self = std::move(self), downAcceptorRequestEp](error_code err, const endpoint &acceptorLocalEp)
	{
		if (err)
		{
			EndWithError(err);
			return;
		}
		SendSocks5(0, acceptorLocalEp, [this, self](error_code err)
		{
			if (err)
			{
				Stop();
				return;
			}
			BeginBindAccept();
			ReadUpWhileAccept();
		});
	});
}

void Socks5Session::BeginBindAccept()
{
	auto self = shared_from_this();

	downAcceptorHandle_.AsyncAccept([this, self = std::move(self)](error_code err, std::unique_ptr<prx_tcp_socket> &&socket)
	{
		downTcp_ = std::move(socket);
		if (err)
		{
			EndWithError(err);
			return;
		}

		EndBind();
	});
}

void Socks5Session::EndBind()
{
	auto self = shared_from_this();
	error_code err;

	endpoint downRemoteEp;
	downTcp_->remote_endpoint(downRemoteEp, err);
	if (err)
	{
		EndWithError(err);
		return;
	}

	if (replySent_.exchange(true))
		return;
	SendSocks5(0, downRemoteEp,
		[this, self = std::move(self)](error_code err)
	{
		if (err)
		{
			Stop();
			return;
		}
		RelayDown();
	});
}

void Socks5Session::BeginUdpAssociation(const endpoint &ep)
{
	upUdp_ = server_.NewUpstreamUdpSocket();
	downUdp_ = server_.NewDownstreamUdpSocket();
	if (IsAdvancedProtocol())
		BeginUdpAssociationWithBind(ep);
	else
		BeginUdpAssociationWithOpen(ep);
}

void Socks5Session::BeginUdpAssociationWithOpen(const endpoint &ep)
{
	auto self = shared_from_this();

	if (ep.port() != 0)
	{
		if (ep.addr().is_any())
		{
			endpoint upRemoteEp;
			error_code err;
			upTcp_->remote_endpoint(upRemoteEp, err);
			if (!err)
			{
				upUdpRemoteEp_.set_addr(upRemoteEp.addr());
				upUdpRemoteEp_.set_port(ep.port());
			}
		}
		else
		{
			upUdpRemoteEp_ = ep;
		}
	}
	upUdp_->async_open([this, self = std::move(self)](error_code err)
	{
		if (err)
		{
			EndWithError(err);
			return;
		}
		downUdp_->async_open([this, self](error_code err)
		{
			if (err)
			{
				EndWithError(err);
				return;
			}
			EndUdpAssociation();
		});
	});
}

void Socks5Session::BeginUdpAssociationWithBind(const endpoint &ep)
{
	auto self = shared_from_this();

	upUdp_->async_open([this, self = std::move(self), ep](error_code err)
	{
		if (err)
		{
			EndWithError(err);
			return;
		}
		downUdp_->async_bind(ep,
			[this, self](error_code err)
		{
			if (err)
			{
				EndWithError(err);
				return;
			}
			EndUdpAssociation();
		});
	});
}

void Socks5Session::EndUdpAssociation()
{
	auto self = shared_from_this();
	error_code err;

	endpoint upUdpLocalEp;
	upUdp_->local_endpoint(upUdpLocalEp, err);
	if (err)
	{
		EndWithError(err);
		return;
	}
	endpoint upLocalEp;
	upTcp_->local_endpoint(upLocalEp, err);
	if (!err)
		upUdpLocalEp.set_addr(upLocalEp.addr());

	if (IsAdvancedProtocol())
	{
		SendSocks5(0, upUdpLocalEp, [this, self = std::move(self)](error_code err)
		{
			if (err)
			{
				Stop();
				return;
			}

			endpoint downUdpLocalEp;
			downUdp_->local_endpoint(downUdpLocalEp, err);
			if (err)
			{
				EndWithError(err);
				return;
			}

			if (replySent_.exchange(true))
				return;
			SendSocks5(0, downUdpLocalEp, [this, self](error_code err)
			{
				if (err)
				{
					Stop();
					return;
				}

				ReadUpKeepalive();
				RelayUpUdp(std::make_shared<std::array<byte, kBufSize>>());
				RelayDownUdp(std::make_shared<std::array<byte, kBufSize>>());
			});
		});
	}
	else
	{
		if (replySent_.exchange(true))
			return;
		SendSocks5(0, upUdpLocalEp, [this, self = std::move(self)](error_code err)
		{
			if (err)
			{
				Stop();
				return;
			}

			ReadUpKeepalive();
			RelayUpUdp(std::make_shared<std::array<byte, kBufSize>>());
			RelayDownUdp(std::make_shared<std::array<byte, kBufSize>>());
		});
	}
}

void Socks5Session::EndWithError(error_code errCode)
{
	auto self = shared_from_this();

	if (replySent_.exchange(true))
	{
		Stop();
		return;
	}
	SendSocks5((uint8_t)errCode, kEpZero,
		[this, self = std::move(self)](error_code)
	{
		Stop();
	});
}

void Socks5Session::SendSocks5(uint8_t type, const endpoint &ep, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	try
	{
		PRXSOCKET_MAKE_INPLACE_BUFFER(std::vector<byte>, req, reqHolder);
		socks5::socks5_base::make_s5_header(req, type, ep);

		upTcp_->async_send(const_buffer(req), std::move(reqHolder),
			[this, callback](error_code err)
		{
			try
			{
				if (err)
					throw(socks5::socks5_error(err));
				(*callback)(err);
			}
			catch (const socks5::socks5_error& ex)
			{
				Stop();
				(*callback)(ex.get_err());
			}
			catch (const std::exception &)
			{
				Stop();
				(*callback)(ERR_OPERATION_FAILURE);
			}
		});
	}
	catch (std::exception &)
	{
		Stop();
		(*callback)(ERR_OPERATION_FAILURE);
	}
}

namespace
{
	struct RecvSocks5State
	{
		byte respHead[263];
		size_t respSizeRead = 0;

		uint8_t respCode;
		endpoint respEp;
	};

	bool parse_s5(RecvSocks5State &state, const_buffer &recvBuffer)
	{
		constexpr size_t respSizeMin = 7;
		if (state.respSizeRead < respSizeMin)
		{
			state.respSizeRead += const_buffer::consume(state.respHead + state.respSizeRead, respSizeMin - state.respSizeRead, recvBuffer);
			if (state.respSizeRead < respSizeMin)
				return false;
		}

		size_t sizeNeeded;
		unsigned int atyp = std::to_integer<unsigned int>(state.respHead[3]);
		switch (atyp)
		{
		case 1:
			sizeNeeded = 10;
			break;
		case 3:
			sizeNeeded = respSizeMin + std::to_integer<unsigned char>(state.respHead[4]);
			break;
		case 4:
			sizeNeeded = 22;
			break;
		default:
			throw std::invalid_argument("Invalid ATYP");
		}
		if (state.respSizeRead < sizeNeeded)
		{
			state.respSizeRead += const_buffer::consume(state.respHead + state.respSizeRead, sizeNeeded - state.respSizeRead, recvBuffer);
			if (state.respSizeRead < sizeNeeded)
				return false;
		}

		state.respCode = std::to_integer<unsigned char>(state.respHead[1]);
		switch (atyp)
		{
		case 1:
			state.respEp = endpoint(address_v4(state.respHead + 4), static_cast<port_type>((std::to_integer<unsigned int>(state.respHead[8]) << 8) | std::to_integer<unsigned int>(state.respHead[9])));
			break;
		case 3:
		{
			uint8_t addrLen = std::to_integer<uint8_t>(state.respHead[4]);
			size_t portOffset = (respSizeMin - 2) + addrLen;
			state.respEp = endpoint(address_str((const char *)(state.respHead + 5), addrLen), static_cast<port_type>((std::to_integer<unsigned int>(state.respHead[portOffset]) << 8) | std::to_integer<unsigned int>(state.respHead[portOffset + 1])));
			break;
		}
		case 4:
			state.respEp = endpoint(address_v6(state.respHead + 4), static_cast<port_type>((std::to_integer<unsigned int>(state.respHead[20]) << 8) | std::to_integer<unsigned int>(state.respHead[21])));
			break;
		}
		return true;
	}
}

void Socks5Session::ReceiveSocks5(socks5::socksreq_callback &&complete_handler)
{
	//Max socks5 req size is 262
	static_assert(sizeof(RecvSocks5State::respHead) >= 262, "upBuf_ is too small");

	std::shared_ptr<std::pair<RecvSocks5State, socks5::socksreq_callback>> state_callback = std::make_shared<std::pair<RecvSocks5State, socks5::socksreq_callback>>(RecvSocks5State(), std::move(complete_handler));
	upTcp_->async_recv_until(std::move(upLeftOver_), [this, state_callback](const_buffer &buffer_recv)
	{
		try
		{
			bool header_parsed = parse_s5(state_callback->first, buffer_recv);
			return error_code_or_op_result{ header_parsed ? OPRESULT_COMPLETED : OPRESULT_CONTINUE };
		}
		catch (const std::exception &)
		{
			return error_code_or_op_result{ OPRESULT_ERROR };
		}
	}, [this, state_callback](error_code_or_op_result ec_or_result, buffer_with_data_store &&leftover)
	{
		if (ec_or_result.code == OPRESULT_ERROR) [[unlikely]]
		{
			Stop();
			state_callback->second(ERR_OPERATION_FAILURE, -1, kEpZero);
			return;
		}
		if (ec_or_result.code != OPRESULT_COMPLETED) [[unlikely]]
		{
			Stop();
			state_callback->second(ec_or_result.code != 0 ? ec_or_result.code : ERR_OPERATION_FAILURE, -1, kEpZero);
			return;
		}
		upLeftOver_ = std::move(leftover);
		RecvSocks5State &state = state_callback->first;
		state_callback->second(0, state.respCode, state.respEp);
	});
}

void Socks5Session::RelayUpLeftover()
{
	size_t transferred = upLeftOver_.buffer.size();
	if (transferred == 0)
	{
		RelayUp();
		return;
	}
	auto self = shared_from_this();
	downTcp_->async_send(upLeftOver_.buffer, std::move(upLeftOver_.holder),
		[this, self, transferred](error_code err)
	{
		if (err)
		{
			upTcp_->async_shutdown(prx_tcp_socket::shutdown_receive, [this, self](error_code) {});
			return;
		}
		AddBytesDown(transferred);
		RelayUp();
	});
}

void Socks5Session::RelayUp()
{
	auto self = shared_from_this();
	upTcp_->async_recv([this, self = std::move(self)](error_code err, const_buffer data, buffer_data_store_holder &&dataHolder)
	{
		if (err)
		{
			downTcp_->async_shutdown(prx_tcp_socket::shutdown_send, [this, self](error_code) {});
			return;
		}
		size_t transferred = data.size();
		downTcp_->async_send(data, std::move(dataHolder),
			[this, self, transferred](error_code err)
		{
			if (err)
			{
				upTcp_->async_shutdown(prx_tcp_socket::shutdown_receive, [this, self](error_code) {});
				return;
			}
			AddBytesDown(transferred);
			RelayUp();
		});
	});
}

void Socks5Session::RelayDown()
{
	auto self = shared_from_this();
	downTcp_->async_recv([this, self = std::move(self)](error_code err, const_buffer data, buffer_data_store_holder &&dataHolder)
	{
		if (err)
		{
			upTcp_->async_shutdown(prx_tcp_socket::shutdown_send, [this, self](error_code) {});
			return;
		}
		size_t transferred = data.size();
		upTcp_->async_send(data, std::move(dataHolder),
			[this, self, transferred](error_code err)
		{
			if (err)
			{
				downTcp_->async_shutdown(prx_tcp_socket::shutdown_receive, [this, self](error_code) {});
				return;
			}
			AddBytesUp(transferred);
			RelayDown();
		});
	});
}

void Socks5Session::ReadUpWhileAccept()
{
	// TODO: We should probably buffer the data, instead of discarding them?
	auto self = shared_from_this();
	upLeftOver_.buffer = const_buffer();
	upLeftOver_.holder.reset();
	upTcp_->async_recv([this, self = std::move(self)](error_code err, const_buffer data, buffer_data_store_holder &&dataHolder)
	{
		if (err)
		{
			Stop();
			return;
		}
		if (downTcp_)
		{
			size_t transferred = data.size();
			downTcp_->async_send(data, std::move(dataHolder),
				[this, self, transferred](error_code err)
			{
				if (err)
				{
					upTcp_->async_shutdown(prx_tcp_socket::shutdown_receive, [this, self](error_code) {});
					return;
				}
				AddBytesDown(transferred);
				RelayUp();
			});
			return;
		}
		ReadUpWhileAccept();
	});
}

void Socks5Session::ReadUpKeepalive()
{
	auto self = shared_from_this();
	upLeftOver_.buffer = const_buffer();
	upLeftOver_.holder.reset();
	upTcp_->async_recv([this, self = std::move(self)](error_code err, const_buffer, buffer_data_store_holder &&holder)
	{
		if (err)
		{
			Stop();
			return;
		}
		holder.reset();
		ReadUpKeepalive();
	});
}

void Socks5Session::RelayUpUdp(const std::shared_ptr<std::array<byte, kBufSize>> &upBuf)
{
	auto self = shared_from_this();

	upUdp_->async_recv_from(upUdpFrom_, mutable_buffer(upBuf->data(), upBuf->size()),
		[this, self = std::move(self), upBuf](error_code err, size_t transferred)
	{
		if (err)
		{
			if (upUdp_->is_open())
				RelayUpUdp(upBuf);
			else
				Stop();
			return;
		}
		if (upUdpRemoteEp_.port() == 0)
			upUdpRemoteEp_ = upUdpFrom_;

		endpoint dst;
		const byte *dataStartAt;
		size_t dataSize;
		err = ParseUdp(upBuf->data(), transferred, dst, dataStartAt, dataSize);
		if (err)
		{
			RelayUpUdp(upBuf);
			return;
		}

		downUdp_->async_send_to(dst, const_buffer(dataStartAt, dataSize),
			[this, self, upBuf, dataSize](error_code err)
		{
			if (err && !downUdp_->is_open())
			{
				Stop();
				return;
			}
			AddBytesDown(dataSize);
			RelayUpUdp(upBuf);
		});
	});
}

void Socks5Session::RelayDownUdp(const std::shared_ptr<std::array<byte, kBufSize>> &downBuf)
{
	auto self = shared_from_this();

	downUdp_->async_recv_from(downUdpFrom_, mutable_buffer(downBuf->data(), downBuf->size()),
		[this, self = std::move(self), downBuf](error_code err, size_t transferred)
	{
		if (err)
		{
			if (downUdp_->is_open())
				RelayDownUdp(downBuf);
			else
				Stop();
			return;
		}
		if (upUdpRemoteEp_.port() == 0)
		{
			RelayDownUdp(downBuf);
			return;
		}

		std::shared_ptr<std::vector<byte>> buf = std::make_shared<std::vector<byte>>();
		try
		{
			std::vector<byte> &header = *buf;
			socks5::socks5_base::make_s5_header(header, 0, downUdpFrom_);
			header[0] = header[1] = header[2] = byte{ 0 }; //RSV && FRAG

			upUdp_->async_send_to(upUdpRemoteEp_, const_buffer(*buf),
				[this, self, downBuf, buf, transferred](error_code err)
			{
				if (err && !upUdp_->is_open())
				{
					Stop();
					return;
				}
				AddBytesUp(transferred);
				RelayDownUdp(downBuf);
			});
		}
		catch (std::exception &)
		{
			RelayDownUdp(downBuf);
			return;
		}
	});
}

error_code Socks5Session::ParseUdp(const byte *recv, size_t recvSize, endpoint &ep, const byte *&dataStartAt, size_t &dataSize)
{
	try
	{
		dataSize = 0;

		for (int i = 0; i < 3; i++)
			if (recv[i] != byte{ 0 })
				return ERR_OPERATION_FAILURE;

		size_t headerSize = 0;
		switch (static_cast<unsigned char>(recv[3]))
		{
		case 1:
			if (recvSize < 10)
				return ERR_OPERATION_FAILURE;
			headerSize = 10;
			ep = endpoint(address_v4(recv + 4), static_cast<port_type>((std::to_integer<unsigned int>(recv[8]) << 8) | std::to_integer<unsigned int>(recv[9])));
			break;
		case 3:
		{
			if (recvSize < 7)
				return ERR_OPERATION_FAILURE;
			uint8_t addrLen = std::to_integer<uint8_t>(recv[4]);
			if (recvSize < static_cast<size_t>(7) + addrLen)
				return ERR_OPERATION_FAILURE;
			size_t portOffset = static_cast<size_t>(5) + addrLen;
			ep = endpoint(address_str((const char *)(recv + 5), addrLen), static_cast<port_type>((std::to_integer<unsigned int>(recv[portOffset]) << 8) | std::to_integer<unsigned int>(recv[portOffset + 1])));
			headerSize = static_cast<size_t>(7) + addrLen;
			break;
		}
		case 4:
			if (recvSize < 22)
				return ERR_OPERATION_FAILURE;
			headerSize = 22;
			ep = endpoint(address_v6(recv + 4), static_cast<port_type>((std::to_integer<unsigned int>(recv[20]) << 8) | std::to_integer<unsigned int>(recv[21])));
			break;
		}
		if (headerSize == 0)
			return ERR_OPERATION_FAILURE;

		dataStartAt = recv + headerSize;
		dataSize = recvSize - headerSize;
	}
	catch (std::exception &)
	{
		return ERR_OPERATION_FAILURE;
	}
	return 0;
}

uint8_t Socks5Session::SelectMethod(int argc, const uint8_t* argv)
{
	for (const uint8_t *av_end = argv + argc; argv < av_end; argv++)
	{
		switch (*argv)
		{
		case 0x00:
		case 0x80:
			return *argv;
		}
	}
	return 0xFF;
}

bool Socks5Session::IsAdvancedProtocol()
{
	switch (selectedMethod)
	{
	case 0x00:
		return false;
	case 0x80:
		return true;
	}
	return false;
}
