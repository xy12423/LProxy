#include "pch.h"
#include "ProxyServer.h"
#include "Socks4Session.h"
#include "Socks5Session.h"
#include "AcceptorManager.h"

ProxyServer::ProxyServer(asio::io_context &ioContext, const endpoint &acceptorLocalEp)
	:ioContext_(ioContext), acceptorLocalEp_(acceptorLocalEp), acceptorRetryTimer_(ioContext)
{
}

ProxyServer::~ProxyServer()
{
}

void ProxyServer::Start()
{
	stopping_ = false;
	Accept();
}

void ProxyServer::Stop()
{
	if (stopping_.exchange(true))
		return;
	std::lock_guard<std::recursive_mutex> lockSessions(sessionsMutex_);
	std::lock_guard<std::recursive_mutex> lockAcceptor(acceptorMutex_);

	boost::system::error_code ec;
	acceptorRetryTimer_.cancel(ec);
	error_code err;
	acceptor_->close(err);
	for (const auto &p : sessions_)
	{
		auto sess = p.second.lock();
		if (sess)
			sess->Stop();
	}
}

void ProxyServer::BeginSession(ProxySession *sessPtr, std::weak_ptr<ProxySession> &&sessWeak)
{
	std::lock_guard<std::recursive_mutex> lock(sessionsMutex_);
	if (stopping_)
		return;

	auto sess = sessWeak.lock();
	assert(&*sess == sessPtr);
	if (sess)
		sessions_.insert_or_assign(sessPtr, sessWeak);
}

void ProxyServer::EndSession(ProxySession *sess)
{
	std::lock_guard<std::recursive_mutex> lock(sessionsMutex_);

	std::cout << "End ";
	PrintSession(*sess);
	sessions_.erase(sess);
}

void ProxyServer::PrintSession(const ProxySession &sess)
{
	std::cout << sess.SessionType() << '\t';
	std::cout << sess.UpstreamEndpoint().addr().to_string() << ':' << sess.UpstreamEndpoint().port() << '\t';
	std::cout << sess.DownstreamEndpoint().addr().to_string() << ':' << sess.DownstreamEndpoint().port() << '\t';
	std::cout << sess.TotalBytesUp() << " Bytes up\t";
	std::cout << sess.TotalBytesDown() << " Bytes down" << std::endl;
}

void ProxyServer::PrintSessions()
{
	std::lock_guard<std::recursive_mutex> lock(sessionsMutex_);

	for (const auto &weakSession : sessions_)
		if (auto session = weakSession.second.lock())
			PrintSession(*session);
}

void ProxyServer::Accept()
{
	std::lock_guard<std::recursive_mutex> lock(acceptorMutex_);
	if (stopping_)
		return;

	if (!acceptor_)
	{
		InitAcceptor();
		return;
	}
	acceptor_->async_accept([this](error_code err, std::unique_ptr<prx_tcp_socket> &&socketPtr)
	{
		if (err)
		{
			InitAcceptor();
			return;
		}

		prx_tcp_socket &socket = *socketPtr;
		std::shared_ptr<std::unique_ptr<prx_tcp_socket>> sharedSocketPtr = std::make_shared<std::unique_ptr<prx_tcp_socket>>(std::move(socketPtr));
		std::shared_ptr<char> firstByte = std::make_shared<char>();
		async_read(socket, mutable_buffer(&*firstByte, 1),
			[this, sharedSocketPtr = std::move(sharedSocketPtr), firstByte](error_code err)
		{
			if (err)
				return;

			switch (*firstByte)
			{
			case 4:
			{
				auto session = std::make_shared<Socks4Session>(*this, std::move(*sharedSocketPtr));
				session->Start(*firstByte);
				break;
			}
			case 5:
			{
				auto session = std::make_shared<Socks5Session>(*this, std::move(*sharedSocketPtr));
				session->Start(*firstByte);
				break;
			}
			}
		});

		Accept();
	});
}

void ProxyServer::InitAcceptor()
{
	std::lock_guard<std::recursive_mutex> lock(acceptorMutex_);
	if (stopping_)
		return;

	acceptor_.reset(NewUpstreamAcceptor());
	acceptorRetrying_ = false;
	acceptor_->async_open([this](error_code err)
	{
		if (err)
		{
			InitAcceptorFailed();
			return;
		}
		acceptor_->async_bind(acceptorLocalEp_,
			[this](error_code err)
		{
			if (err)
			{
				InitAcceptorFailed();
				return;
			}
			acceptor_->async_listen([this](error_code err)
			{
				if (err)
				{
					InitAcceptorFailed();
					return;
				}
				Accept();
			});
		});
	});
}

void ProxyServer::InitAcceptorFailed()
{
	if (acceptorRetrying_.exchange(true))
		return;
	std::lock_guard<std::recursive_mutex> lock(acceptorMutex_);
	if (stopping_)
		return;

	acceptor_->async_close([this](error_code)
	{
		std::lock_guard<std::recursive_mutex> lock(acceptorMutex_);
		if (stopping_)
			return;

		acceptorRetryTimer_.expires_after(std::chrono::seconds(5));
		acceptorRetryTimer_.async_wait([this](const boost::system::error_code &ec)
		{
			if (!ec)
				InitAcceptor();
		});
	});
}
