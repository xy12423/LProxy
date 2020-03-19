#include "pch.h"
#include "LoadBalancingManager.h"

/*
VConnID 4b 0
Seq     4b 4
Ack     4b 8
Flags   1b 12
Wnd     1b 13
Len     2b 14
*/

template <typename T, typename ...TArgs>
inline static void SafeCallback(T &callback, TArgs &&...args)
{
	T func = std::move(callback);
	callback = nullptr;
	func(std::forward<TArgs>(args)...);
}

void LoadBalancingManager::VirtualConnection::AsyncStart(null_callback &&completeHandler)
{
	AppendSendSegment(SYN, nullptr, 0, std::move(completeHandler));
}

void LoadBalancingManager::VirtualConnection::AsyncSendData(const const_buffer &buffer, prx_tcp_socket::transfer_callback &&completeHandler)
{
	std::shared_ptr<prx_tcp_socket::transfer_callback> callback = std::make_shared<prx_tcp_socket::transfer_callback>(completeHandler);
	size_t transferring = std::min(buffer.size(), kMaxSegmentSize);
	AppendSendSegment(0, buffer.data(), transferring,
		[this, transferring, callback](error_code err)
	{
		if (err)
		{
			(*callback)(err, 0);
			return;
		}
		(*callback)(0, transferring);
	});
}

void LoadBalancingManager::VirtualConnection::AppendSendSegment(uint8_t flags, const char *payload, uint16_t payloadSize, SegmentCallback &&completeHandler)
{
	thread_local std::vector<char> segmentData;
	//Construct segment (except seq, ack and wnd)
	segmentData.resize(16 + payloadSize);
	char *data = segmentData.data();
	uint32_t virtualConnectionIdLE = boost::endian::native_to_little(virtualConnectionId_);
	memcpy(data, &virtualConnectionIdLE, 4);
	data[12] = flags;
	uint16_t payloadSizeLE = boost::endian::native_to_little(payloadSize);
	memcpy(data + 14, &payloadSizeLE, 2);
	memcpy(data + 16, payload, payloadSize);
	return AppendSendSegment(flags, std::move(segmentData), std::move(completeHandler));
}

void LoadBalancingManager::VirtualConnection::AppendSendSegment(uint8_t flags, const_buffer_sequence &&payload, SegmentCallback &&completeHandler)
{
	thread_local std::vector<char> segmentData;
	//Construct segment (except seq, ack and wnd)
	uint16_t payloadSize = std::min(payload.size_total(), kMaxSegmentSize);
	segmentData.resize(16 + payloadSize);
	char *data = segmentData.data();
	uint32_t virtualConnectionIdLE = boost::endian::native_to_little(virtualConnectionId_);
	memcpy(data, &virtualConnectionIdLE, 4);
	data[12] = flags;
	uint16_t payloadSizeLE = boost::endian::native_to_little(payloadSize);
	memcpy(data + 14, &payloadSizeLE, 2);
	payload.gather(data + 16, payloadSize);
	return AppendSendSegment(flags, std::move(segmentData), std::move(completeHandler));
}

void LoadBalancingManager::VirtualConnection::AppendSendSegment(uint8_t flags, std::vector<char> &&segmentWithPartOfHeader, SegmentCallback &&completeHandler)
{
	std::unique_lock<std::recursive_mutex> lock(mutex_);
	if (closed_)
	{
		completeHandler(ERR_OPERATION_FAILURE);
		return;
	}
	if ((shutdownFlags_ & SHUTDOWN_SEND) && !(flags & RST))
	{
		completeHandler(ERR_OPERATION_FAILURE);
		return;
	}

	bool isAck = (flags & ACK) || (flags & RST);
	uint32_t sendSegmentId = sendSegmentIdNext_;
	if (!isAck)
		++sendSegmentIdNext_; //ACKs don't take new segid

	std::shared_ptr<SendSegment> sendingSegment = std::make_shared<SendSegment>(ioContext_, sendSegmentId, isAck);
	sendingSegment->data = std::move(segmentWithPartOfHeader);
	uint32_t sendSegmentIdLE = boost::endian::native_to_little(sendSegmentId);
	memcpy(sendingSegment->data.data() + 4, &sendSegmentIdLE, 4); //Set seq

	if (flags & FIN)
		shutdownFlags_ |= SHUTDOWN_SEND;
	if (flags & RST)
		shutdownFlags_ |= SHUTDOWN_RESET;
	if (sendSegmentId - sendLaskAck_ > sendWindow_)
	{
		assert(!sendCallback_);
		std::shared_ptr<SegmentCallback> callback = std::make_shared<SegmentCallback>(completeHandler);
		sendSegmentIdPending_ = sendSegmentId;
		sendCallback_ = [this, sendingSegment, callback](error_code err)
		{
			if (err)
			{
				(*callback)(err);
				return;
			}
			ioContext_.post([this, self = shared_from_this(), sendingSegment, callback]()
			{
				std::unique_lock<std::recursive_mutex> lock(mutex_);
				if (closed_)
				{
					(*callback)(ERR_OPERATION_FAILURE);
					return;
				}
				sendSegments_.push_back(std::move(sendingSegment));
				lock.unlock();
				BeginSendSegment();
				(*callback)(0);
			});
		};
	}
	else
	{
		sendSegments_.push_back(std::move(sendingSegment));
		lock.unlock();
		BeginSendSegment();
		completeHandler(0);
	}
}

void LoadBalancingManager::VirtualConnection::BeginSendSegment()
{
	std::unique_lock<std::recursive_mutex> lock(mutex_);
	if (closed_)
		return;
	if (!inQueue_)
	{
		bool dataReady = false;
		auto itr = sendSegments_.begin(), itrEnd = sendSegments_.end();
		while (!dataReady && itr != itrEnd)
		{
			const auto &segment = *itr;
			if (segment->segmentId - sendLaskAck_ > sendWindow_)
				break;
			switch (segment->state)
			{
			case SendSegment::READY:
				//Found, breaking
				dataReady = true;
				break;
			case SendSegment::SENT:
				++itr;
				break;
			case SendSegment::ACKNOWLEDGED: //Shoudn't happen
				assert(false);
			}
		}
		if (!dataReady)
			return;
		inQueue_ = true;
		lock.unlock();
		parent_.AppendPendingSendSegment(virtualConnectionId_);
	}
}

void LoadBalancingManager::VirtualConnection::BeginSendSegmentAck()
{
	std::unique_lock<std::recursive_mutex> lock(mutex_);
	if (closed_)
		return;
	if (!inQueue_)
	{
		inQueue_ = true;
		lock.unlock();
		parent_.AppendPendingSendSegment(virtualConnectionId_);
	}
}

void LoadBalancingManager::VirtualConnection::OnSendSegment(const std::shared_ptr<Connection> &connection)
{
	std::unique_lock<std::recursive_mutex> lock(mutex_);
	if (closed_)
		return;

	inQueue_ = false;

	std::shared_ptr<SendSegment> sendingSegment;
	auto itr = sendSegments_.begin(), itrEnd = sendSegments_.end();
	while (!sendingSegment && itr != itrEnd)
	{
		const auto &segment = *itr;
		if (segment->segmentId - sendLaskAck_ > sendWindow_)
			break;
		switch (segment->state)
		{
		case SendSegment::READY:
			sendingSegment = segment;
			//Erase if it's ACK since it doesn't need to be ACKed
			if (sendingSegment->isAcknowledgement)
				sendSegments_.erase(itr);
			break;
		case SendSegment::SENT:
			++itr;
			break;
		case SendSegment::ACKNOWLEDGED: //Shoudn't happen
			assert(false);
		}
	}
	bool sendingPureAck = false;
	if (!sendingSegment)
	{
		sendingPureAck = true;

		//Make a ACK segment

		uint32_t sendSegmentId = sendSegmentIdNext_;
		sendingSegment = std::make_shared<SendSegment>(ioContext_, sendSegmentId, true);
		sendingSegment->data.resize(16);
		char *data = sendingSegment->data.data();
		uint32_t virtualConnectionIdLE = boost::endian::native_to_little(virtualConnectionId_);
		memcpy(data, &virtualConnectionIdLE, 4);
		uint32_t sendSegmentIdNextLE = boost::endian::native_to_little(sendSegmentId);
		memcpy(data + 4, &sendSegmentIdNextLE, 4);
		data[12] = ACK;
		data[14] = data[15] = 0;
	}

	uint32_t ackLE = boost::endian::native_to_little(receiveSegmentIdOffset_ + receiveSegmentComplete_);
	assert(sendingSegment->data.size() >= 16);
	memcpy(sendingSegment->data.data() + 8, &ackLE, 4);
	sendingSegment->data[13] = (uint8_t)(kMaxWindowSize - receiveSegmentComplete_ - 1);

	sendingSegment->state = SendSegment::SENT;
	++sendingSegment->tryCount;
	if (!sendingSegment->isAcknowledgement) //ACK doesn't need retransmission
	{
		sendingSegment->retryTimer.expires_after(std::chrono::milliseconds(std::min(kTimeRetryMin, connection->RTT())));
		sendingSegment->retryTimer.async_wait([this, self = shared_from_this(), sendingSegment, tryCount = sendingSegment->tryCount](const boost::system::error_code &ec)
		{
			if (!ec)
				RetrySendSegment(sendingSegment, tryCount);
		});
	}

	lock.unlock();
	connection->Socket()->async_write(const_buffer(sendingSegment->data),
		[this, self = shared_from_this(), connection, sendingSegment, tryCount = sendingSegment->tryCount](error_code err)
	{
		if (err)
		{
			connection->SetConnectionFailed();
			connection->ReleaseConnection();
			RetrySendSegment(sendingSegment, tryCount);
		}
		else
		{
			connection->ReleaseConnection();
		}
	});
	if (sendingSegment->data[12] & RST) //RST sent
	{
		lock.lock();
		if (closed_)
			return;
		ShutdownCheck();
		return;
	}
	if (!sendingPureAck) //Pure ACK only appears when nothing is ready
		BeginSendSegment();
}

void LoadBalancingManager::VirtualConnection::RetrySendSegment(const std::shared_ptr<SendSegment> &sendingSegment, size_t tryCount)
{
	if (sendingSegment->isAcknowledgement) //ACK doesn't need retransmission
		return;
	std::unique_lock<std::recursive_mutex> lock(mutex_);
	if (closed_)
		return;
	if (sendingSegment->state != SendSegment::SENT || sendingSegment->tryCount != tryCount) //Prevents re-retransmission
		return;
	sendingSegment->state = SendSegment::READY;
	sendingSegment->retryTimer.cancel();
	lock.unlock();
	BeginSendSegment();
}

void LoadBalancingManager::VirtualConnection::AsyncReceiveData(const mutable_buffer &buffer, prx_tcp_socket::transfer_callback &&completeHandler)
{
	std::unique_lock<std::recursive_mutex> lock(mutex_);
	if (closed_)
	{
		lock.unlock();
		completeHandler(ERR_OPERATION_FAILURE, 0);
		return;
	}
	if (receiveSegmentComplete_ >= 0x80000000)
	{
		std::shared_ptr<prx_tcp_socket::transfer_callback> callback = std::make_shared<prx_tcp_socket::transfer_callback>(completeHandler);
		assert(!receiveCallback_);
		receiveCallback_ = [this, buffer, callback](error_code err)
		{
			if (err)
			{
				(*callback)(err, 0);
				return;
			}
			ioContext_.post([this, self = shared_from_this(), buffer, callback]()
			{
				AsyncReceiveData(buffer, std::move(*callback));
			});
		};
		return;
	}
	size_t transferred;
	bool windowChanged = ConsumeReceiveSegment(buffer.data(), buffer.size(), transferred);
	lock.unlock();
	completeHandler(0, transferred);
	if (windowChanged)
		BeginSendSegmentAck();
}

void LoadBalancingManager::VirtualConnection::OnReceiveSegment(const char *data, size_t size)
{
	uint32_t seq, ack;
	memcpy(&seq, data + 4, 4);
	boost::endian::little_to_native_inplace(seq);
	memcpy(&ack, data + 8, 4);
	boost::endian::little_to_native_inplace(ack);
	uint8_t flags = data[12];
	uint8_t wnd = data[13];

	std::unique_lock<std::recursive_mutex> lock(mutex_);
	if (closed_)
		return;
	if (shutdownFlags_ & SHUTDOWN_RECEIVE)
	{
		if (flags & RST) //Process only RST after SHUTDOWN_RECEIVE is set (FIN received)
		{
			shutdownFlags_ |= SHUTDOWN_RESET;
			ShutdownCheck();
			return;
		}
		if (!(flags & ACK)) //Other things are discarded, just send an ACK if needed
		{
			lock.unlock();
			BeginSendSegmentAck();
		}
		return;
	}

	bool ackIsValid = sendSegments_.empty() ? (ack == sendLaskAck_) : (ack - sendLaskAck_ < 0x80000000 && sendSegments_.back()->segmentId - ack < 0x80000000);
	if (ackIsValid)
	{
		auto itr = sendSegments_.begin(), itrEnd = sendSegments_.end();
		for (; itr != itrEnd; ++itr)
		{
			const auto &segment = *itr;
			if (ack - segment->segmentId >= 0x80000000)
				break;
			segment->state = SendSegment::ACKNOWLEDGED;
			if (segment->data[12] & FIN)
			{
				assert(itr == --sendSegments_.end());
				shutdownFlags_ |= SHUTDOWN_SENT;
				ShutdownCheck();
			}
		}
		sendSegments_.erase(sendSegments_.begin(), itr);
		sendLaskAck_ = ack;
		sendWindow_ = wnd;
	}
	else
	{
		if (ack - sendLaskAck_ >= 0x40000000 && ack - sendLaskAck_ < 0xC0000000)
		{
			lock.unlock();
			Reset();
			return;
		}
	}

	//Process special flags
	if (flags & RST)
	{
		shutdownFlags_ |= SHUTDOWN_RESET;
		ShutdownCheck();
		return;
	}
	bool needAck = true;
	if (flags & ACK)
	{
		needAck = false;
	}
	else
	{
		//Try reassemble
		size_t segmentIndex = seq - receiveSegmentIdOffset_;
		if (segmentIndex < kMaxWindowSize)
		{
			auto &receiveSegment = receiveSegments_[segmentIndex];
			if (receiveSegment.ok)
			{
				if (receiveSegment.flags != flags || receiveSegment.data.size() != size - 16)
				{
					lock.unlock();
					Reset();
					return;
				}
			}
			else
			{
				//Received new segment
				receiveSegment.ok = true;
				receiveSegment.flags = flags;
				receiveSegment.data.assign(data + 16, data + size);
				if (segmentIndex + 1 > receiveSegmentCount_)
					receiveSegmentCount_ = segmentIndex + 1;

				//Reassemble
				uint32_t i = 0;
				for (; i < receiveSegmentCount_; ++i)
				{
					if (!receiveSegments_[i].ok)
						break;
					if (receiveSegments_[i].flags & FIN)
					{
						//FIN appeared, discard all segments after that, set SHUTDOWN_RECEIVE
						for (uint32_t j = ++i; j < receiveSegmentCount_; ++j)
							receiveSegments_[j].ok = false;
						shutdownFlags_ |= SHUTDOWN_RECEIVE;
						ShutdownCheck();
						if (!(shutdownFlags_ & SHUTDOWN_SEND))
							ioContext_.post([this, self = shared_from_this()]() { Shutdown(); });
						break;
					}
				}
				receiveSegmentComplete_ = i - 1;
				if (receiveCallback_ && i > 0)
				{
					SafeCallback(receiveCallback_, 0);
				}
			}
		}
	}

	if (ackIsValid) //Valid ACK received, send queue and send window updated, check send callback
	{
		if (sendCallback_ && sendSegmentIdPending_ - sendLaskAck_ <= sendWindow_)
		{
			SafeCallback(sendCallback_, 0);
		}
	}
	if (needAck) //Send an ACK if needed
	{
		lock.unlock();
		BeginSendSegmentAck();
	}
}

bool LoadBalancingManager::VirtualConnection::ConsumeReceiveSegment(char *dst, size_t dstSize, size_t &transferred)
{
	size_t srcIndex = 0;
	transferred = 0;
	while (receiveSegmentComplete_ - srcIndex < 0x80000000 && dstSize > 0)
	{
		assert(receiveSegments_[srcIndex].ok);
		size_t copying = std::min(dstSize, receiveSegments_[srcIndex].data.size() - receiveSegmentDataOffset_);
		memcpy(dst, receiveSegments_[srcIndex].data.data() + receiveSegmentDataOffset_, copying);
		transferred += copying;
		receiveSegmentDataOffset_ += copying;
		dstSize -= copying;
		if (receiveSegmentDataOffset_ >= receiveSegments_[srcIndex].data.size())
		{
			receiveSegments_[srcIndex].ok = false;
			++srcIndex;
			receiveSegmentDataOffset_ = 0;
		}
	}
	if (srcIndex > 0)
	{
		for (uint32_t i = 0; srcIndex + i < kMaxWindowSize; ++i)
			std::swap(receiveSegments_[i], receiveSegments_[srcIndex + i]);
		receiveSegmentIdOffset_ += srcIndex;
		receiveSegmentComplete_ -= srcIndex;
		receiveSegmentCount_ -= srcIndex;
		return true;
	}
	return false;
}

void LoadBalancingManager::VirtualConnection::Shutdown()
{
	AppendSendSegment(FIN, nullptr, 0, [](error_code) {});
}

void LoadBalancingManager::VirtualConnection::Reset()
{
	AppendSendSegment(RST, nullptr, 0, [](error_code) {});
}

void LoadBalancingManager::VirtualConnection::ShutdownCheck()
{
	if ((shutdownFlags_ & SHUTDOWN_COMPLETE) == SHUTDOWN_COMPLETE && (!shutdownTimerSet_ || (shutdownFlags_ & SHUTDOWN_FORCE)))
	{
		if (sendCallback_)
		{
			SafeCallback(sendCallback_, ERR_OPERATION_FAILURE);
		}
		if (receiveCallback_)
		{
			SafeCallback(receiveCallback_, ERR_OPERATION_FAILURE);
		}
		if (shutdownFlags_ & SHUTDOWN_FORCE)
		{
			shutdownTimer_.cancel();
			closed_ = true;
			ioContext_.post([this, self = shared_from_this()]() { parent_.OnVirtualConnectionClosed(virtualConnectionId_); });
		}
		else
		{
			shutdownTimer_.async_wait([this, self = shared_from_this()](const boost::system::error_code &ec)
			{
				if (!ec)
				{
					std::unique_lock<std::recursive_mutex> lock(mutex_);
					if (closed_)
						return;
					closed_ = true;
					lock.unlock();
					parent_.OnVirtualConnectionClosed(virtualConnectionId_);
				}
			});
		}
		shutdownTimerSet_ = true;
	}
}

void LoadBalancingManager::AsyncConnect(std::function<void(error_code, uint32_t)> &&completeHandler)
{
	thread_local CryptoPP::AutoSeededRandomPool prng;
	std::unique_lock<std::recursive_mutex> generalLock(generalMutex_);
	uint32_t vConnId;
	do
	{
		vConnId = prng.GenerateWord32();
	} while (virtualConnections_.count(vConnId) > 0);
	std::shared_ptr<VirtualConnection> virtualConnection = std::make_shared<VirtualConnection>(vConnId, ioContext_, *this);
	virtualConnections_.emplace(vConnId, virtualConnection);
	generalLock.unlock();
	auto callback = std::make_shared<std::function<void(error_code, uint32_t)>>(std::move(completeHandler));
	virtualConnection->AsyncStart([this, callback, vConnId](error_code err)
	{
		if (err)
		{
			(*callback)(err, 0);
			return;
		}
		(*callback)(0, vConnId);
	});
}

void LoadBalancingManager::AsyncAccept(std::function<void(error_code, uint32_t)> &&completeHandler)
{
	std::unique_lock<std::recursive_mutex> generalLock(generalMutex_);
	if (acceptQueue_.empty())
	{
		auto callback = std::make_shared<std::function<void(error_code, uint32_t)>>(std::move(completeHandler));
		acceptCallback_ = [this, callback](error_code err)
		{
			if (err)
			{
				(*callback)(err, 0);
				return;
			}
			ioContext_.post([this, callback]()
			{
				AsyncAccept(std::move(*callback));
			});
		};
		return;
	}
	uint32_t vConnId = acceptQueue_.front();
	acceptQueue_.pop_front();
	generalLock.unlock();
	completeHandler(0, vConnId);
}

void LoadBalancingManager::AppendPendingSendSegment(uint32_t virtualConnectionId)
{
	std::unique_lock<std::recursive_mutex> generalLock(generalMutex_);
	if (!requestQueueSet_.insert(virtualConnectionId).second)
		return;
	bool needDispatch = requestQueue_.empty() && !idleConnections_.empty();
	requestQueue_.push_back(virtualConnectionId);
	if (needDispatch)
	{
		generalLock.unlock();
		DispatchPendingSendSegment();
	}
}

void LoadBalancingManager::DispatchPendingSendSegment()
{
	std::unique_lock<std::recursive_mutex> generalLock(generalMutex_);
	if (requestQueue_.empty())
		return;
	if (idleConnections_.empty())
		return;

	std::shared_ptr<Connection> connection = std::make_shared<Connection>(*this);
	if (*connection)
		return;

	std::shared_ptr<VirtualConnection> virtualConnection;
	while (!virtualConnection && !requestQueue_.empty())
	{
		auto itr = virtualConnections_.find(requestQueue_.front());
		requestQueueSet_.erase(requestQueue_.front());
		requestQueue_.pop_front();
		if (itr != virtualConnections_.end())
		{
			virtualConnection = itr->second;
			break;
		}
	}
	if (!virtualConnection)
		return;

	generalLock.unlock();
	virtualConnection->OnSendSegment(connection);
}

void LoadBalancingManager::ReceiveSegment(const std::shared_ptr<BaseConnection> &receiveSocket)
{
	receiveSocket->socket->async_read(mutable_buffer(receiveSocket->receiveBuffer, 16),
		[this, receiveSocket](error_code err)
	{
		if (err)
		{
			EndReceiveSegmentWithError(receiveSocket);
			return;
		}
		uint16_t len;
		memcpy(&len, receiveSocket->receiveBuffer + 14, 2);
		boost::endian::little_to_native_inplace(len);
		if (len == 0)
		{
			EndReceiveSegment(receiveSocket, len);
			ReceiveSegment(receiveSocket);
		}
		else
		{
			receiveSocket->socket->async_read(mutable_buffer(receiveSocket->receiveBuffer + 16, len),
				[this, receiveSocket, len](error_code err)
			{
				if (err)
				{
					EndReceiveSegmentWithError(receiveSocket);
					return;
				}
				EndReceiveSegment(receiveSocket, len);
				ReceiveSegment(receiveSocket);
			});
		}
	});
}

void LoadBalancingManager::EndReceiveSegment(const std::shared_ptr<BaseConnection> &receiveSocket, size_t len)
{
	uint32_t vConnId;
	memcpy(&vConnId, receiveSocket->receiveBuffer, 4);
	std::shared_ptr<VirtualConnection> virtualConnection;

	std::unique_lock<std::recursive_mutex> generalLock(generalMutex_);
	auto itr = virtualConnections_.find(vConnId);
	if (itr == virtualConnections_.end())
	{
		uint8_t flags = receiveSocket->receiveBuffer[12];
		if (flags & RST)
			return;
		if (!(flags & SYN))
		{
			virtualConnection = std::make_shared<VirtualConnection>(vConnId, ioContext_, *this);
			virtualConnections_.emplace(vConnId, virtualConnection);
			//Not releasing lock to ensure Reset first
			virtualConnection->Reset();
			return;
		}
		//SYN
		if (acceptQueue_.size() > kAcceptQueueMax)
			return; //Drop
		virtualConnection = std::make_shared<VirtualConnection>(vConnId, ioContext_, *this);
		virtualConnections_.emplace(vConnId, virtualConnection);
		acceptQueue_.push_back(vConnId);
		if (acceptCallback_)
		{
			SafeCallback(acceptCallback_, 0);
		}
	}
	else
	{
		virtualConnection = itr->second;
	}
	generalLock.unlock();
	virtualConnection->OnReceiveSegment(receiveSocket->receiveBuffer, 16 + len);
}

void LoadBalancingManager::EndReceiveSegmentWithError(const std::shared_ptr<BaseConnection> &receiveSocket)
{
	std::unique_lock<std::recursive_mutex> generalLock(generalMutex_);
	auto itr = idleConnections_.find(receiveSocket->index);
	if (itr != idleConnections_.end())
	{
		idleConnections_.erase(itr);
		generalLock.unlock();
		receiveSocket->socket->async_close([this, receiveSocket](error_code)
		{
			ioContext_.post([this, receiveSocket]() { InitConnection(receiveSocket->index); });
		});
	}
	else
	{
		generalLock.unlock();
		receiveSocket->socket->async_close([this, receiveSocket](error_code) {});
	}
}

void LoadBalancingManager::OnVirtualConnectionClosed(uint32_t virtualConnectionId)
{
	std::lock_guard<std::recursive_mutex> generalLock(generalMutex_);
	virtualConnections_.erase(virtualConnectionId);
}

std::shared_ptr<LoadBalancingManager::BaseConnection> LoadBalancingManager::OccupyConnection()
{
	std::lock_guard<std::recursive_mutex> generalLock(generalMutex_);
	if (idleConnections_.empty())
		return std::shared_ptr<BaseConnection>();
	auto itr = idleConnections_.begin();
	std::shared_ptr<BaseConnection> ret = std::move(itr->second);
	idleConnections_.erase(itr);
	return ret;
}

void LoadBalancingManager::ReleaseConnection(std::shared_ptr<BaseConnection> &&conn, bool failed)
{
	if (failed)
	{
		std::shared_ptr<BaseConnection> connection = std::move(conn);
		connection->socket->async_close([this, connection](error_code)
		{
			ioContext_.post([this, connection]() { InitConnection(connection->index); });
		});
		return;
	}
	std::unique_lock<std::recursive_mutex> generalLock(generalMutex_);
	bool needDispatch = !requestQueue_.empty() && idleConnections_.empty();
	if (!idleConnections_.emplace(conn->index, std::move(conn)).second)
		return;
	if (needDispatch)
	{
		generalLock.unlock();
		DispatchPendingSendSegment();
	}
}

void LoadBalancingManager::InitConnection(size_t index)
{
	NewBaseTcpSocket(index,
		[this, index](std::unique_ptr<prx_tcp_socket> &&socket, uint16_t rtt)
	{
		if (!socket)
			return;
		std::shared_ptr<BaseConnection> baseConnection = std::make_shared<BaseConnection>(index, std::move(socket), rtt);
		ReceiveSegment(baseConnection);
		ReleaseConnection(std::move(baseConnection), false);
	});
}
