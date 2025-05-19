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
#include "Socks4Session.h"
#include "ProxyServer.h"

static endpoint kEpZero((uint32_t)0, 0);

Socks4Session::Socks4Session(ProxyServer &server, std::unique_ptr<prx_tcp_socket> &&socket)
	:ProxySession(server), upTcp_(std::move(socket))
{
	error_code err;
	upTcp_->remote_endpoint(AccessUpstreamEndpoint(), err);
	if (err)
		AccessUpstreamEndpoint() = endpoint();
	AccessSessionType() = "Socks4";
}

Socks4Session::~Socks4Session()
{
	if (!stopping_)
		Stop();
}

void Socks4Session::Start()
{
	auto self = shared_from_this();
	server_.BeginSession(this, std::weak_ptr<ProxySession>(self));

	ReceiveRequest();
}

void Socks4Session::Start(buffer_with_data_store &&leftover)
{
	auto self = shared_from_this();
	server_.BeginSession(this, std::weak_ptr<ProxySession>(self));

	upLeftOver_ = std::move(leftover);
	ReceiveRequest();
}

void Socks4Session::Stop()
{
	if (stopping_.exchange(true))
		return;

	downAcceptorHandle_.CancelAccept();
	error_code ec;
	if (upTcp_)
		upTcp_->close(ec);
	if (downTcp_)
		downTcp_->close(ec);
}

namespace
{
	struct RecvSocks4State
	{
		static constexpr size_t respSizeMax = 256;

		byte respHead[respSizeMax];
		size_t respSizeRead = 0;

		size_t userNameEnd = respSizeMax, domainEnd = respSizeMax;

		bool isSocks4a() const { return respHead[4] == byte{ 0 } && respHead[5] == byte{ 0 } && respHead[6] == byte{ 0 } && respHead[7] != byte{ 0 }; }
	};

	bool parse_s4(RecvSocks4State &state, const_buffer &recv_buffer)
	{
		constexpr size_t respSizeMin = 8;
		if (state.respSizeRead < respSizeMin)
		{
			state.respSizeRead += const_buffer::consume(state.respHead + state.respSizeRead, respSizeMin - state.respSizeRead, recv_buffer);
			if (state.respSizeRead < respSizeMin)
				return false;
		}

		if (state.userNameEnd == RecvSocks4State::respSizeMax)
		{
			size_t sizeToConsume = 0;
			for (; sizeToConsume < recv_buffer.size(); ++sizeToConsume)
			{
				if (recv_buffer.data()[sizeToConsume] == byte{ 0 })
				{
					sizeToConsume += 1;
					break;
				}
			}
			if (state.respSizeRead + sizeToConsume > RecvSocks4State::respSizeMax)
				throw std::invalid_argument("Header too long");
			state.respSizeRead += const_buffer::consume(state.respHead + state.respSizeRead, sizeToConsume, recv_buffer);
			if (state.respHead[state.respSizeRead - 1] == byte{ 0 })
				state.userNameEnd = state.respSizeRead;
			else
				return false;
		}

		if (state.isSocks4a() && state.domainEnd == RecvSocks4State::respSizeMax)
		{
			size_t sizeToConsume = 0;
			for (; sizeToConsume < recv_buffer.size(); ++sizeToConsume)
			{
				if (recv_buffer.data()[sizeToConsume] == byte{ 0 })
				{
					sizeToConsume += 1;
					break;
				}
			}
			if (state.respSizeRead + sizeToConsume > RecvSocks4State::respSizeMax)
				throw std::invalid_argument("Header too long");
			state.respSizeRead += const_buffer::consume(state.respHead + state.respSizeRead, sizeToConsume, recv_buffer);
			if (state.respHead[state.respSizeRead - 1] == byte{ 0 })
				state.domainEnd = state.respSizeRead;
			else
				return false;
		}

		return true;
	}
}

void Socks4Session::ReceiveRequest()
{
	std::shared_ptr<RecvSocks4State> state_callback = std::make_shared<RecvSocks4State>();
	upTcp_->async_recv_until(std::move(upLeftOver_), [this, state_callback](const_buffer &buffer_recv)
	{
		try
		{
			bool header_parsed = parse_s4(*state_callback, buffer_recv);
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
			return;
		}
		if (ec_or_result.code != OPRESULT_COMPLETED) [[unlikely]]
		{
			Stop();
			return;
		}
		upLeftOver_ = std::move(leftover);
		RecvSocks4State &state = *state_callback;

		if (state.isSocks4a())
		{
			AccessSessionType() = "Socks4a";
			DoRequest(
				std::to_integer<uint8_t>(state.respHead[1]),
				endpoint(
					std::string(reinterpret_cast<const char *>(state.respHead + state.userNameEnd), state.domainEnd - state.userNameEnd),
					(std::to_integer<uint8_t>(state.respHead[2]) << 8u) | std::to_integer<uint8_t>(state.respHead[3])
				)
			);
		}
		else
		{
			DoRequest(
				std::to_integer<uint8_t>(state.respHead[1]),
				endpoint(
					address_v4(state.respHead + 4),
					(std::to_integer<uint8_t>(state.respHead[2]) << 8u) | std::to_integer<uint8_t>(state.respHead[3])
				)
			);
		}
	});
}

void Socks4Session::DoRequest(uint8_t cmd, const endpoint &ep)
{
	AccessDownstreamEndpoint() = ep;

	switch (cmd)
	{
	case CONNECT:
		AccessSessionType().append(" Connect");
		BeginConnect(ep);
		break;
	case BIND:
		AccessSessionType().append(" Bind");
		BeginBind(ep);
		break;
	default:
		Stop();
		return;
	}

	server_.PrintSession(*this);
}

void Socks4Session::BeginConnect(const endpoint &ep)
{
	auto self = shared_from_this();

	downTcp_ = server_.NewDownstreamTcpSocket();
	downTcp_->async_open([this, self = std::move(self), ep](error_code err)
	{
		if (err)
		{
			EndWithError();
			return;
		}
		downTcp_->async_connect(ep, [this, self](error_code err)
		{
			if (err)
			{
				EndWithError();
				return;
			}
			EndConnect();
		});
	});
}

void Socks4Session::EndConnect()
{
	auto self = shared_from_this();

	if (replySent_.exchange(true))
		return;
	SendResponse(90, kEpZero,
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

void Socks4Session::BeginBind(const endpoint &ep)
{
	auto self = shared_from_this();

	downAcceptorHandle_.AsyncPrepare(kEpZero,
		[this]()->std::unique_ptr<prx_listener> { return std::unique_ptr<prx_listener>(server_.NewDownstreamAcceptor()); },
		[this, self = std::move(self), ep](error_code err, const endpoint &acceptorLocalEp)
	{
		if (err)
		{
			EndWithError();
			return;
		}
		SendResponse(90, acceptorLocalEp, [this, self, ep](error_code err)
		{
			if (err)
			{
				Stop();
				return;
			}
			ReadUpWhileAccept();
			BeginBindAccept(ep);
		});
	});
}

void Socks4Session::BeginBindAccept(const endpoint &ep)
{
	auto self = shared_from_this();

	downAcceptorHandle_.AsyncAccept([this, self = std::move(self), ep](error_code err, std::unique_ptr<prx_tcp_socket> &&socket)
	{
		downTcp_ = std::move(socket);
		if (err)
		{
			EndWithError();
			return;
		}

		EndBind(ep);
	});
}

void Socks4Session::EndBind(const endpoint &ep)
{
	auto self = shared_from_this();
	error_code err;

	endpoint downRemoteEp;
	downTcp_->remote_endpoint(downRemoteEp, err);
	if (err)
	{
		EndWithError();
		return;
	}
	if (downRemoteEp.addr() != ep.addr())
	{
		EndWithError();
		return;
	}

	if (replySent_.exchange(true))
		return;
	SendResponse(90, downRemoteEp,
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

void Socks4Session::EndWithError()
{
	auto self = shared_from_this();

	if (replySent_.exchange(true))
	{
		Stop();
		return;
	}
	SendResponse(91, kEpZero,
		[this, self = std::move(self)](error_code)
	{
		Stop();
	});
}

void Socks4Session::SendResponse(uint8_t err, const endpoint &ep, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	try
	{
		PRXSOCKET_MAKE_INPLACE_BUFFER(std::vector<byte>, resp, respHolder);
		resp.push_back(byte{ kReplyVersion });  //VER
		resp.push_back(byte{ err });            //REP
		resp.insert(resp.end(), { byte{ static_cast<unsigned char>(ep.port() >> 8) }, byte{ static_cast<unsigned char>(ep.port() & 0xFF) } });	//DSTPORT
		if (ep.addr().type() != address::V4)
			throw(socks5::socks5_error(ERR_BAD_ARG_LOCAL));
		const byte *addr_data = ep.addr().v4().data();
		resp.insert(resp.end(), addr_data, addr_data + address_v4::ADDR_SIZE);  //DSTADDR

		upTcp_->async_send(const_buffer(resp), std::move(respHolder),
			[this, callback](error_code err)
		{
			try
			{
				if (err)
					throw(socks5::socks5_error(err));
				(*callback)(err);
			}
			catch (socks5::socks5_error& ex)
			{
				Stop();
				(*callback)(ex.get_err());
			}
			catch (std::exception &)
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

void Socks4Session::RelayUpLeftover()
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

void Socks4Session::RelayUp()
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

void Socks4Session::RelayDown()
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

void Socks4Session::ReadUpWhileAccept()
{
	// TODO: We should probably buffer the data, instead of discarding them?
	auto self = shared_from_this();
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
