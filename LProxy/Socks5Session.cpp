#include "pch.h"
#include "Socks5Session.h"
#include "ProxyServer.h"

static endpoint kEpZero((uint32_t)0, 0);

Socks5Session::Socks5Session(ProxyServer &server, std::unique_ptr<prx_tcp_socket_base> &&socket)
	:ProxySession(server), upTcp_(std::move(socket)),
	upBuf_(std::make_unique<char[]>(kBufSize)), downBuf_(std::make_unique<char[]>(kBufSize))
{
	error_code err;
	upTcp_->local_endpoint(AccessUpstreamEndpoint(), err);
	if (err)
		AccessUpstreamEndpoint() = endpoint();
	AccessTypeInfo() = "Socks5";
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
	static_assert(kBufSize >= 257, "upBuf_ is too small");

	async_read(*upTcp_, mutable_buffer(upBuf_.get(), 2),
		[this, self = std::move(self)](error_code err)
	{
		if (err)
		{
			Stop();
			return;
		}
		if (upBuf_[0] != kSocksVersion)
		{
			Stop();
			return;
		}
		ReceiveMethodRequested();
	});
}

void Socks5Session::ReceiveMethodRequested()
{
	auto self = shared_from_this();

	async_read(*upTcp_, mutable_buffer(mutable_buffer(upBuf_.get() + 2, (uint8_t)upBuf_[1])),
		[this, self = std::move(self)](error_code err)
	{
		if (err)
		{
			Stop();
			return;
		}
		selectedMethod = SelectMethod((uint8_t)upBuf_[1], (uint8_t*)(upBuf_.get() + 2));
		SendMethodSelected();
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
		if (err)
		{
			Stop();
			return;
		}
		AccessDownstreamEndpoint() = ep;
		switch (cmd)
		{
		case CONNECT:
			AccessTypeInfo().append(" Connect");
			BeginConnect(ep);
			break;
		case BIND:
			AccessTypeInfo().append(" Bind");
			if (IsAdvancedProtocol())
				AccessTypeInfo().append(" Advanced");
			BeginBind(ep);
			break;
		case UDP_ASSOCIATE:
			AccessTypeInfo().append(" Udp Associate");
			if (IsAdvancedProtocol())
				AccessTypeInfo().append(" Advanced");
			BeginUdpAssociation(ep);
			break;
		}
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
		{
			Stop();
			return;
		}
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
		{
			Stop();
			return;
		}
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
			SendSocks5(0, downUdpLocalEp, [this, self = std::move(self)](error_code err)
			{
				if (err)
				{
					Stop();
					return;
				}

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
			{
				Stop();
				return;
			}

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

	//Max socks5 req size is 262
	static_assert(kBufSize >= 262, "upBuf_ is too small");

	async_read(*upTcp_, mutable_buffer(upBuf_.get(), 5),
		[this, callback](error_code err)
	{
		try
		{
			if (err)
				throw(socks5_error(err));
			if (upBuf_[0] != kSocksVersion || upBuf_[2] != 0) //VER && RSV
				throw(socks5_error(ERR_BAD_ARG_REMOTE));
			RecvSocks5Body(callback);
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

void Socks5Session::RecvSocks5Body(const std::shared_ptr<socksreq_callback> &callback)
{
	size_t bytesLast;
	switch (upBuf_[3])	//ATYP
	{
	case 1: //V4
		bytesLast = address_v4::addr_size + 1;
		break;
	case 3: //STR
		bytesLast = upBuf_[4] + 2;
		break;
	case 4: //V6
		bytesLast = address_v6::addr_size + 1;
		break;
	default:
		throw(socks5_error(ERR_UNSUPPORTED));
	}
	async_read(*upTcp_, mutable_buffer(upBuf_.get() + 5, bytesLast),
		[this, bytesLast, callback](error_code err)
	{
		try
		{
			if (err)
				throw(socks5_error(err));

			address bndAddr;
			bndAddr.from_socks5(upBuf_.get() + 3); //Begin from ATYP
			port_type bndPort = ((uint8_t)(upBuf_[bytesLast + 3]) << 8) | (uint8_t)(upBuf_[bytesLast + 4]);
			(*callback)(0, upBuf_[1], endpoint(bndAddr, bndPort));
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

error_code Socks5Session::ParseUdp(const char *recv, size_t recvSize, endpoint &ep, const char *&dataStartAt, size_t &dataSize)
{
	try
	{
		dataSize = 0;

		for (int i = 0; i < 3; i++)
			if (recv[i] != 0)
				return WARN_OPERATION_FAILURE;

		address dst_addr;
		size_t addr_size = dst_addr.from_socks5(recv + 3);
		if (addr_size == 0 || 5 + addr_size >= recvSize)
			return WARN_OPERATION_FAILURE;

		ep = endpoint(
			std::move(dst_addr),
			((uint8_t)(recv[3 + addr_size]) << 8) | (uint8_t)(recv[4 + addr_size])
		);
		dataStartAt = recv + 5 + addr_size;
		dataSize = recvSize - (5 + addr_size);
	}
	catch (std::exception &)
	{
		return WARN_OPERATION_FAILURE;
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
