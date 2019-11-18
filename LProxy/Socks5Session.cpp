#include "pch.h"
#include "Socks5Session.h"
#include "ProxyServer.h"
#include "AcceptorManager.h"

static endpoint kLocalEpZero(address(static_cast<uint32_t>(0)), 0);

uint8_t methodSelector(int argc, const uint8_t* argv)
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
	:ProxySession(server), socks5_base(std::move(socket)),
	upBuf_(std::make_unique<char[]>(kBufSize)), downBuf_(std::make_unique<char[]>(kBufSize))
{
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

	async_select(sockssel_callback(methodSelector),
		[this, self = std::move(self)](error_code err)
	{
		if (err)
		{
			Stop();
			return;
		}
		if (get_auth_method() == 0xFF)
		{
			Stop();
			return;
		}
		ReceiveRequest();
	});
}

void Socks5Session::Stop()
{
	if (stopping_.exchange(true))
		return;

	if (downAcceptorEp_.get_addr().get_type() != address::UNDEFINED)
		AcceptorManager::CancelAccept(downAcceptorEp_, downAcceptorId_);
	error_code ec;
	if (downTcp_)
		downTcp_->close(ec);
	if (upUdp_)
		upUdp_->close(ec);
	if (downUdp_)
		downUdp_->close(ec);
}

void Socks5Session::ReceiveRequest()
{
	auto self = shared_from_this();

	async_recv_s5([this, self = std::move(self)](error_code err, uint8_t cmd, const endpoint& ep)
	{
		try
		{
			if (err)
				return;
			switch (cmd)
			{
			case CONNECT:
				BeginConnect(ep);
				break;
			case BIND:
				BeginBind(ep);
				break;
			case UDP_ASSOCIATE:
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
	async_send_s5(0, (err ? kLocalEpZero : downLocalEp),
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

	endpoint downAcceptorRequestEp = (get_auth_method() == 0x80 ? ep : kLocalEpZero);
	AcceptorManager::AsyncPrepare(downAcceptorRequestEp,
		[this]()->prx_listener_base* { return server_.NewDownstreamAcceptor(); },
		[this, self = std::move(self), downAcceptorRequestEp](error_code err, const endpoint &acceptorLocalEp)
	{
		if (err)
		{
			EndWithError(err);
			return;
		}
		async_send_s5(0, acceptorLocalEp, [this, self = std::move(self), downAcceptorRequestEp](error_code err)
		{
			if (err)
				return;
			ReadUpWhileAccept();
			BeginBindAccept(downAcceptorRequestEp);
		});
	});
}

void Socks5Session::BeginBindAccept(const endpoint &ep)
{
	auto self = shared_from_this();

	downAcceptorEp_ = ep;
	downAcceptorId_ = AcceptorManager::AsyncAccept(ep,
		[this, self = std::move(self)](error_code err, prx_tcp_socket_base* socket)
	{
		downTcp_.reset(socket);
		downAcceptorEp_ = endpoint();
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
	async_send_s5(0, downRemoteEp,
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
	switch (get_auth_method())
	{
	case 0x00:
		BeginUdpAssociationWithOpen(ep);
		break;
	case 0x80:
		BeginUdpAssociationWithBind(ep);
		break;
	}
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
			access_socket().remote_endpoint(upRemoteEp, err);
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
	access_socket().local_endpoint(upLocalEp, err);
	if (!err)
		upUdpLocalEp.set_addr(upLocalEp.get_addr());

	if (get_auth_method() != 0x80)
		if (replySent_.exchange(true))
			return;
	async_send_s5(0, upUdpLocalEp, [this, self = std::move(self)](error_code err)
	{
		if (err)
			return;

		if (get_auth_method() == 0x80)
		{
			endpoint downUdpLocalEp;
			downUdp_->local_endpoint(downUdpLocalEp, err);
			if (err)
			{
				EndWithError(err);
				return;
			}

			if (replySent_.exchange(true))
				return;
			async_send_s5(0, downUdpLocalEp, [this, self = std::move(self)](error_code err)
			{
				if (err)
					return;

				udpOverTcpBuf_ = std::make_unique<char[]>(kBufSize);
				RelayUpUdpOverTcp();
				RelayUpUdp();
				RelayDownUdp();
			});
		}
		else
		{
			ReadUpKeepalive();
			RelayUpUdp();
			RelayDownUdp();
		}
	});
}

void Socks5Session::EndWithError(error_code errCode)
{
	auto self = shared_from_this();

	if (replySent_.exchange(true))
	{
		Stop();
		return;
	}
	async_send_s5((uint8_t)errCode, kLocalEpZero,
		[this, self = std::move(self)](error_code)
	{
		Stop();
	});
}

void Socks5Session::RelayUp()
{
	auto self = shared_from_this();
	async_recv(mutable_buffer(upBuf_.get(), kBufSize),
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
		async_write(access_socket(), const_buffer(downBuf_.get(), transferred),
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
	async_recv(mutable_buffer(upBuf_.get(), kBufSize),
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
		err = parse_udp(upBuf_.get(), transferred, dst, dataStartAt, dataSize);
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

	async_read(access_socket(), mutable_buffer(udpOverTcpBuf_.get(), 2),
		[this, self = std::move(self)](error_code err)
	{
		if (err)
		{
			Stop();
			return;
		}

		uint16_t size = (uint8_t)udpOverTcpBuf_[0] | ((uint8_t)udpOverTcpBuf_[1] << 8u);
		async_read(access_socket(), mutable_buffer(udpOverTcpBuf_.get() + 2, size - 2),
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
			err = parse_udp(udpOverTcpBuf_.get(), size, dst, dataStartAt, dataSize);
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
		if (upUdpRemoteEp_.get_port() == 0 && get_auth_method() != 0x80)
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
				size_t buf_size = buf->size();
				(*buf)[0] = (uint8_t)(buf_size);
				(*buf)[1] = (uint8_t)(buf_size >> 8);

				async_write(access_socket(), const_buffer(*buf),
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
	async_recv(mutable_buffer(&udpKeepAliveBuf_, 1),
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
