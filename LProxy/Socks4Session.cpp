#include "pch.h"
#include "Socks4Session.h"
#include "ProxyServer.h"

static endpoint kEpZero((uint32_t)0, 0);

Socks4Session::Socks4Session(ProxyServer &server, std::unique_ptr<prx_tcp_socket> &&socket)
	:ProxySession(server), upTcp_(std::move(socket)),
	upBuf_(std::make_unique<char[]>(kBufSize)), downBuf_(std::make_unique<char[]>(kBufSize))
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

void Socks4Session::Start(char firstByte)
{
	auto self = shared_from_this();
	server_.BeginSession(this, std::weak_ptr<ProxySession>(self));

	upBuf_[upBufPEnd_++] = firstByte;
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

void Socks4Session::ReceiveRequest()
{
	assert(upBufP_ <= upBufPEnd_);
	if (upBufP_ + kFixedHeaderSize > upBufPEnd_)
	{
		auto self = shared_from_this();
		ReceiveMore([this, self = std::move(self)](error_code err)
		{
			if (err)
			{
				Stop();
				return;
			}
			ReceiveRequest();
		});
		return;
	}

	if (upBuf_[0] != kSocksVersion)
	{
		Stop();
		return;
	}
	upBufP_ += kFixedHeaderSize;
	ReceiveUsername(upBufP_);
}

void Socks4Session::ReceiveUsername(size_t upBufPBegin)
{
	if (upBufP_ >= upBufPEnd_)
	{
		assert(upBufP_ == upBufPEnd_);
		auto self = shared_from_this();
		ReceiveMore([this, self = std::move(self), upBufPBegin](error_code err)
		{
			if (err)
			{
				Stop();
				return;
			}
			ReceiveUsername(upBufPBegin);
		});
		return;
	}

	while (upBufP_ < upBufPEnd_)
	{
		if (upBuf_[upBufP_] == 0)
		{
			username_.assign(upBuf_.get() + upBufPBegin, upBufP_ - upBufPBegin);
			++upBufP_;

			if (upBuf_[4] == 0 && upBuf_[5] == 0 && upBuf_[6] == 0 && upBuf_[7] != 0)
			{
				AccessSessionType() = "Socks4a";
				ReceiveDomain(upBufP_);
			}
			else
			{
				DoRequest((uint8_t)upBuf_[1], endpoint(address_v4(upBuf_.get() + 4), ((uint8_t)upBuf_[2] << 8) | ((uint8_t)upBuf_[3])));
			}

			return;
		}
		++upBufP_;
	}

	if (upBufPEnd_ < kBufSize)
		ReceiveUsername(upBufPBegin);
	else
		Stop();
}

void Socks4Session::ReceiveDomain(size_t upBufPBegin)
{
	if (upBufP_ >= upBufPEnd_)
	{
		assert(upBufP_ == upBufPEnd_);
		auto self = shared_from_this();
		ReceiveMore([this, self = std::move(self), upBufPBegin](error_code err)
		{
			if (err)
			{
				Stop();
				return;
			}
			ReceiveDomain(upBufPBegin);
		});
		return;
	}

	while (upBufP_ < upBufPEnd_)
	{
		if (upBuf_[upBufP_] == 0)
		{
			std::string domain(upBuf_.get() + upBufPBegin, upBufP_ - upBufPBegin);
			++upBufP_;

			DoRequest((uint8_t)upBuf_[1], endpoint(std::move(domain), ((uint8_t)upBuf_[2] << 8) | ((uint8_t)upBuf_[3])));

			return;
		}
		++upBufP_;
	}

	if (upBufPEnd_ < kBufSize)
		ReceiveDomain(upBufPBegin);
	else
		Stop();
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

	downTcp_.reset(server_.NewDownstreamTcpSocket());
	downTcp_->async_open([this, self = std::move(self), ep](error_code err)
	{
		if (err)
		{
			EndWithError();
			return;
		}
		downTcp_->async_connect(ep, [this, self = std::move(self)](error_code err)
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
		RelayUpBuf();
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
		SendResponse(90, acceptorLocalEp, [this, self = std::move(self), ep](error_code err)
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

void Socks4Session::ReceiveMore(null_callback &&complete_handler)
{
	if (upBufPEnd_ >= kBufSize)
	{
		assert(upBufPEnd_ == kBufSize);
		complete_handler(ERR_OPERATION_FAILURE);
		return;
	}
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	upTcp_->async_recv(mutable_buffer(upBuf_.get() + upBufPEnd_, kBufSize - upBufPEnd_),
		[this, callback = std::move(callback)](error_code err, size_t transferred)
	{
		if (err)
		{
			Stop();
			(*callback)(err);
			return;
		}
		upBufPEnd_ += transferred;
		(*callback)(err);
	});
}

void Socks4Session::SendResponse(uint8_t err, const endpoint &ep, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	try
	{
		std::shared_ptr<std::string> buf = std::make_shared<std::string>();
		buf->push_back(kReplyVersion);  //VER
		buf->push_back(err);            //REP
		buf->push_back(ep.port() >> 8);	//DSTPORT
		buf->push_back(ep.port() & 0xFF);
		if (ep.addr().type() != address::V4)
			throw(socks5_error(ERR_BAD_ARG_LOCAL));
		buf->append(ep.addr().v4().data(), address_v4::addr_size);  //DSTADDR

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

void Socks4Session::RelayUpBuf()
{
	if (upBufP_ >= upBufPEnd_)
	{
		assert(upBufP_ == upBufPEnd_);
		RelayUp();
		return;
	}
	auto self = shared_from_this();
	async_write(*downTcp_, const_buffer(upBuf_.get() + upBufP_, upBufPEnd_ - upBufP_),
		[this, self = std::move(self)](error_code err)
	{
		if (err)
		{
			Stop();
			return;
		}
		AddBytesDown(upBufPEnd_ - upBufP_);
		upBufP_ = upBufPEnd_ = 0;
		RelayUp();
	});
}

void Socks4Session::RelayUp()
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
			[this, self = std::move(self), transferred](error_code err)
		{
			if (err)
			{
				Stop();
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
	downTcp_->async_recv(mutable_buffer(downBuf_.get(), kBufSize),
		[this, self = std::move(self)](error_code err, size_t transferred)
	{
		if (err)
		{
			Stop();
			return;
		}
		async_write(*upTcp_, const_buffer(downBuf_.get(), transferred),
			[this, self = std::move(self), transferred](error_code err)
		{
			if (err)
			{
				Stop();
				return;
			}
			AddBytesUp(transferred);
			RelayDown();
		});
	});
}

void Socks4Session::ReadUpWhileAccept()
{
	auto self = shared_from_this();
	upTcp_->async_recv(mutable_buffer(upBuf_.get() + upBufPEnd_, std::min((size_t)1, kBufSize - upBufPEnd_)),
		[this, self = std::move(self)](error_code err, size_t transferred)
	{
		if (err)
		{
			Stop();
			return;
		}
		upBufPEnd_ += transferred;
		if (downTcp_)
		{
			RelayUpBuf();
			return;
		}
		if (upBufPEnd_ >= kBufSize)
		{
			Stop();
			return;
		}
		ReadUpWhileAccept();
	});
}
