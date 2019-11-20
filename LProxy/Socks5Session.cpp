#include "pch.h"
#include "Socks5Session.h"
#include "ProxyServer.h"

static endpoint kEpZero(address(static_cast<uint32_t>(0)), 0);

static uint8_t methodSelector(int argc, const uint8_t* argv)
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

Socks5Session::Socks5Session(ProxyServer &server, std::unique_ptr<prx_tcp_socket_base> &&socket)
	:ProxySession(server), upTcp_(std::move(socket)),
	upBuf_(std::make_unique<char[]>(kBufSize)), downBuf_(std::make_unique<char[]>(kBufSize))
{
	error_code err;
	upTcp_->local_endpoint(AccessUpstreamEndpoint(), err);
	if (err)
		AccessUpstreamEndpoint() = endpoint();
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

	//Max size of a vaild header is 257
	std::shared_ptr<std::array<char, 257>> headerBuffer = std::make_shared<std::array<char, 257>>();
	async_read(*upTcp_, mutable_buffer(headerBuffer->data(), 2),
		[this, self = std::move(self), headerBuffer](error_code err)
	{
		try
		{
			if (err)
				throw(socks5_error(err));
			if ((*headerBuffer)[0] != kSocksVersion)
				throw(socks5_error(ERR_BAD_ARG_REMOTE));
			ReceiveMethodRequested(headerBuffer);
		}
		catch (socks5_error &)
		{
			Stop();
			return;
		}
		catch (std::exception &)
		{
			Stop();
			return;
		}
	});
}

void Socks5Session::ReceiveMethodRequested(const std::shared_ptr<std::array<char, 257>> &headerBuffer)
{
	auto self = shared_from_this();

	async_read(*upTcp_, mutable_buffer(mutable_buffer(headerBuffer->data() + 2, (uint8_t)(*headerBuffer)[1])),
		[this, self = std::move(self), headerBuffer](error_code err)
	{
		try
		{
			if (err)
				throw(socks5_error(err));
			selectedMethod = methodSelector((uint8_t)(*headerBuffer)[1], (uint8_t*)(headerBuffer->data() + 2));
			SendMethodSelected();
		}
		catch (socks5_error &)
		{
			Stop();
			return;
		}
		catch (std::exception &)
		{
			Stop();
			return;
		}
	});
}

void Socks5Session::SendMethodSelected()
{
	auto self = shared_from_this();

	std::shared_ptr<std::array<char, 2>> methodSelected = std::make_shared<std::array<char, 2>>();
	(*methodSelected)[0] = kSocksVersion;
	(*methodSelected)[1] = selectedMethod;
	async_write(*upTcp_, const_buffer(methodSelected->data(), methodSelected->size()),
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

	RecvSocks5([this, self = std::move(self)](error_code err, uint8_t cmd, const endpoint& ep)
	{
		try
		{
			if (err)
				return;
			AccessDownstreamEndpoint() = ep;
			switch (cmd)
			{
			case CONNECT:
				AccessTypeInfo() = "Socks5 Connect";
				BeginConnect(ep);
				break;
			case BIND:
				AccessTypeInfo() = "Socks5 Bind";
				if (IsAdvancedProtocol())
					AccessTypeInfo().append(" Advanced");
				BeginBind(ep);
				break;
			case UDP_ASSOCIATE:
				AccessTypeInfo() = "Socks5 Udp Associate";
				if (IsAdvancedProtocol())
					AccessTypeInfo().append(" Advanced");
				BeginUdpAssociation(ep);
				break;
			}
		}
		catch (std::exception &) { return; }
	});
}

void Socks5Session::BeginConnect(const endpoint &ep)
{
	auto self = shared_from_this();

	downTcp_.reset(server_.NewDownstreamTcpSocket());
	downTcp_->async_open([this, self = std::move(self), ep](error_code err)
	{
		if (err)
		{
			EndWithError(err);
			return;
		}
		downTcp_->async_connect(ep, [this, self = std::move(self)](error_code err)
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
			return;
		RelayUp();
		RelayDown();
	});
}

void Socks5Session::BeginBind(const endpoint &ep)
{
	auto self = shared_from_this();

	endpoint downAcceptorRequestEp = (IsAdvancedProtocol() ? ep : kEpZero);
	downAcceptorHandle_.AsyncPrepare(downAcceptorRequestEp,
		[this]()->prx_listener_base* { return server_.NewDownstreamAcceptor(); },
		[this, self = std::move(self), downAcceptorRequestEp](error_code err, const endpoint &acceptorLocalEp)
	{
		if (err)
		{
			EndWithError(err);
			return;
		}
		SendSocks5(0, acceptorLocalEp, [this, self = std::move(self)](error_code err)
		{
			if (err)
				return;
			ReadUpWhileAccept();
			BeginBindAccept();
		});
	});
}

void Socks5Session::BeginBindAccept()
{
	auto self = shared_from_this();

	downAcceptorHandle_.AsyncAccept([this, self = std::move(self)](error_code err, prx_tcp_socket_base* socket)
	{
		downTcp_.reset(socket);
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
			return;
		RelayDown();
	});
}

void Socks5Session::BeginUdpAssociation(const endpoint &ep)
{
	upUdp_.reset(server_.NewUpstreamUdpSocket());
	downUdp_.reset(server_.NewDownstreamUdpSocket());
	if (IsAdvancedProtocol())
		BeginUdpAssociationWithBind(ep);
	else
		BeginUdpAssociationWithOpen(ep);
}

void Socks5Session::BeginUdpAssociationWithOpen(const endpoint &ep)
{
	auto self = shared_from_this();

	if (ep.get_port() != 0)
	{
		if (ep.get_addr().is_any())
		{
			endpoint upRemoteEp;
			error_code err;
			upTcp_->remote_endpoint(upRemoteEp, err);
			if (!err)
			{
				upUdpRemoteEp_.set_addr(upRemoteEp.get_addr());
				upUdpRemoteEp_.set_port(ep.get_port());
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
		downUdp_->async_open([this, self = std::move(self)](error_code err)
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
			[this, self = std::move(self)](error_code err)
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
		upUdpLocalEp.set_addr(upLocalEp.get_addr());

	if (IsAdvancedProtocol())
	{
		SendSocks5(0, upUdpLocalEp, [this, self = std::move(self)](error_code err)
		{
			if (err)
				return;

			endpoint downUdpLocalEp;
			downUdp_->local_endpoint(downUdpLocalEp, err);
			if (err)
			{
				EndWithError(err);
				return;
			}

			if (replySent_.exchange(true))
				return;
			SendSocks5(0, downUdpLocalEp, [this, self = std::move(self)](error_code err)
			{
				if (err)
					return;

				udpOverTcpBuf_ = std::make_unique<char[]>(kBufSize);
				RelayUpUdpOverTcp();
				RelayUpUdp();
				RelayDownUdp();
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
				return;

			ReadUpKeepalive();
			RelayUpUdp();
			RelayDownUdp();
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

void Socks5Session::RelayUp()
{
	auto self = shared_from_this();
	upTcp_->async_recv(mutable_buffer(upBuf_.get(), kBufSize),
		[this, self = std::move(self)](error_code err, size_t transferred)
	{
		if (err)
		{
			Stop();
			return;
		}
		async_write(*downTcp_, const_buffer(upBuf_.get(), transferred),
			[this, self = std::move(self)](error_code err)
		{
			if (err)
			{
				Stop();
				return;
			}
			RelayUp();
		});
	});
}

void Socks5Session::RelayDown()
{
	auto self = shared_from_this();
	downTcp_->async_recv(mutable_buffer(downBuf_.get(), kBufSize),
		[this, self = std::move(self)](error_code err, size_t transferred)
	{
		if (err)
		{
			Stop();
			return;
		}
		async_write(*upTcp_, const_buffer(downBuf_.get(), transferred),
			[this, self = std::move(self)](error_code err)
		{
			if (err)
			{
				Stop();
				return;
			}
			RelayDown();
		});
	});
}

void Socks5Session::ReadUpWhileAccept()
{
	auto self = shared_from_this();
	upTcp_->async_recv(mutable_buffer(upBuf_.get(), kBufSize),
		[this, self = std::move(self)](error_code err, size_t transferred)
	{
		if (err)
		{
			Stop();
			return;
		}
		if (downTcp_)
		{
			async_write(*downTcp_, const_buffer(upBuf_.get(), transferred),
				[this, self = std::move(self)](error_code err)
			{
				if (err)
				{
					Stop();
					return;
				}
				RelayUp();
			});
			return;
		}
		ReadUpWhileAccept();
	});
}

void Socks5Session::RelayUpUdp()
{
	auto self = shared_from_this();

	upUdp_->async_recv_from(upUdpFrom_, mutable_buffer(upBuf_.get(), kBufSize),
		[this, self = std::move(self)](error_code err, size_t transferred)
	{
		if (err)
		{
			if (upUdp_->is_open())
				RelayUpUdp();
			else
				Stop();
			return;
		}
		if (upUdpRemoteEp_.get_port() == 0)
			upUdpRemoteEp_ = upUdpFrom_;

		endpoint dst;
		const char *dataStartAt;
		size_t dataSize;
		err = ParseUdp(upBuf_.get(), transferred, dst, dataStartAt, dataSize);
		if (err)
		{
			RelayUpUdp();
			return;
		}

		downUdp_->async_send_to(dst, const_buffer(dataStartAt, dataSize),
			[this, self = std::move(self)](error_code err)
		{
			if (err && !downUdp_->is_open())
			{
				Stop();
				return;
			}
			RelayUpUdp();
		});
	});
}

void Socks5Session::RelayUpUdpOverTcp()
{
	auto self = shared_from_this();

	async_read(*upTcp_, mutable_buffer(udpOverTcpBuf_.get(), 2),
		[this, self = std::move(self)](error_code err)
	{
		if (err)
		{
			Stop();
			return;
		}

		uint16_t size = (uint8_t)udpOverTcpBuf_[0] | ((uint8_t)udpOverTcpBuf_[1] << 8u);
		async_read(*upTcp_, mutable_buffer(udpOverTcpBuf_.get() + 2, size - 2),
			[this, self = std::move(self), size](error_code err)
		{
			if (err)
			{
				Stop();
				return;
			}
			udpOverTcpBuf_[0] = udpOverTcpBuf_[1] = 0;

			endpoint dst;
			const char *dataStartAt;
			size_t dataSize;
			err = ParseUdp(udpOverTcpBuf_.get(), size, dst, dataStartAt, dataSize);
			if (err)
			{
				RelayUpUdpOverTcp();
				return;
			}

			downUdp_->async_send_to(dst, const_buffer(dataStartAt, dataSize),
				[this, self = std::move(self)](error_code err)
			{
				if (err && !downUdp_->is_open())
				{
					Stop();
					return;
				}
				RelayUpUdpOverTcp();
			});
		});
	});
}

void Socks5Session::RelayDownUdp()
{
	auto self = shared_from_this();

	downUdp_->async_recv_from(downUdpFrom_, mutable_buffer(downBuf_.get(), kBufSize),
		[this, self](error_code err, size_t transferred)
	{
		if (err)
		{
			if (downUdp_->is_open())
				RelayDownUdp();
			else
				Stop();
			return;
		}
		if (upUdpRemoteEp_.get_port() == 0 && !IsAdvancedProtocol())
		{
			RelayDownUdp();
			return;
		}

		std::shared_ptr<std::string> buf = std::make_shared<std::string>();
		try
		{
			buf->append(3, '\0');                           //RSV && FRAG
			downUdpFrom_.get_addr().to_socks5(*buf);        //ATYP && DST.ADDR
			buf->push_back(downUdpFrom_.get_port() >> 8);   //DST.PORT
			buf->push_back(downUdpFrom_.get_port() & 0xFF);
			buf->append(downBuf_.get(), transferred);

			if (upUdpRemoteEp_.get_port() != 0)
			{
				upUdp_->async_send_to(upUdpRemoteEp_, const_buffer(*buf),
					[this, self, buf](error_code err)
				{
					if (err && !upUdp_->is_open())
					{
						Stop();
						return;
					}
					RelayDownUdp();
				});
			}
			else
			{
				if (buf->size() > 0xFFFFu)
				{
					RelayDownUdp();
					return;
				}
				size_t bufSize = buf->size();
				(*buf)[0] = (uint8_t)(bufSize);
				(*buf)[1] = (uint8_t)(bufSize >> 8);

				async_write(*upTcp_, const_buffer(*buf),
					[this, buf](error_code err)
				{
					if (err)
					{
						Stop();
						return;
					}
					RelayDownUdp();
				});
			}
		}
		catch (std::exception &)
		{
			RelayDownUdp();
			return;
		}
	});
}

void Socks5Session::ReadUpKeepalive()
{
	auto self = shared_from_this();
	upTcp_->async_recv(mutable_buffer(&udpKeepAliveBuf_, 1),
		[this, self](error_code err, size_t)
	{
		if (err)
		{
			Stop();
			return;
		}
		ReadUpKeepalive();
	});
}

void Socks5Session::SendSocks5(uint8_t type, const endpoint &ep, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	try
	{
		std::shared_ptr<std::string> buf = std::make_shared<std::string>();
		buf->push_back(kSocksVersion);  //VER
		buf->push_back(type);           //CMD / REP
		buf->push_back(0);              //RSV
		ep.get_addr().to_socks5(*buf);  //ATYP && DST.ADDR
		buf->push_back(ep.get_port() >> 8);	//DST.PORT
		buf->push_back(ep.get_port() & 0xFF);

		async_write(*upTcp_, const_buffer(*buf),
			[this, buf, callback](error_code err)
		{
			try
			{
				if (err)
					throw(socks5_error(err));
				(*callback)(err);
			}
			catch (socks5_error& ex)
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

void Socks5Session::RecvSocks5(socksreq_callback &&complete_handler)
{
	std::shared_ptr<socksreq_callback> callback = std::make_shared<socksreq_callback>(complete_handler);

	std::shared_ptr<std::array<char, 263>> buf = std::make_shared<std::array<char, 263>>();
	async_read(*upTcp_, mutable_buffer(buf->data(), 5),
		[this, buf, callback](error_code err)
	{
		try
		{
			if (err)
				throw(socks5_error(err));
			std::array<char, 263> &resp_head = *buf;
			if (resp_head[0] != kSocksVersion || resp_head[2] != 0) //VER && RSV
				throw(socks5_error(ERR_BAD_ARG_REMOTE));
			RecvSocks5Body(buf, callback);
		}
		catch (socks5_error& ex)
		{
			Stop();
			(*callback)(ex.get_err(), -1, kEpZero);
		}
		catch (std::exception &)
		{
			Stop();
			(*callback)(ERR_OPERATION_FAILURE, -1, kEpZero);
		}
	});
}

void Socks5Session::RecvSocks5Body(const std::shared_ptr<std::array<char, 263>> &resp_data, const std::shared_ptr<socksreq_callback> &callback)
{
	std::array<char, 263> &resp_head = *resp_data;
	size_t bytes_last;
	switch (resp_head[3])	//ATYP
	{
	case 1:
		bytes_last = address_v4::addr_size + 1;
		break;
	case 3:
		bytes_last = resp_head[4] + 2;
		break;
	case 4:
		bytes_last = address_v6::addr_size + 1;
		break;
	default:
		throw(socks5_error(ERR_UNSUPPORTED));
	}
	async_read(*upTcp_, mutable_buffer(resp_data->data() + 5, bytes_last),
		[this, bytes_last, resp_data, callback](error_code err)
	{
		try
		{
			if (err)
				throw(socks5_error(err));

			std::array<char, 263> &resp_head = *resp_data;
			address bnd_addr;
			bnd_addr.from_socks5(resp_data->data() + 3);
			port_type bnd_port = ((uint8_t)(resp_head[bytes_last + 3]) << 8) | (uint8_t)(resp_head[bytes_last + 4]);
			(*callback)(0, resp_head[1], endpoint(bnd_addr, bnd_port));
		}
		catch (socks5_error& ex)
		{
			Stop();
			(*callback)(ex.get_err(), -1, kEpZero);
		}
		catch (std::exception &)
		{
			Stop();
			(*callback)(ERR_OPERATION_FAILURE, -1, kEpZero);
		}
	});
}

error_code Socks5Session::ParseUdp(const char *recv, size_t recvSize, endpoint &ep, const char *&dataStartAt, size_t &dataSize)
{
	return error_code();
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
