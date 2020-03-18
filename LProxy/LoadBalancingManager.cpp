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

void LoadBalancingManager::VirtualConnection::AppendSendSegment(uint8_t flags, const char *payload, uint16_t payloadSize, SegmentCallback &&completeHandler)
{
	std::unique_lock<std::recursive_mutex> lock(mutex_);
	if (closed)
		return;

	bool isAck = (flags & ACK) || (flags & RST);
	uint32_t sendSegmentId = sendSegmentIdNext_;
	if (!isAck)
		++sendSegmentIdNext_; //ACKs don't take new segid

	lock.unlock();

	std::shared_ptr<SendSegment> sendingSegment = std::make_shared<SendSegment>(ioContext_, sendSegmentId, isAck);
	sendingSegment->data.resize(16 + payloadSize);
	char *data = sendingSegment->data.data();
	uint32_t virtualConnectionIdLE = boost::endian::native_to_little(virtualConnectionId_);
	memcpy(data, &virtualConnectionIdLE, 4);
	uint32_t sendSegmentIdLE = boost::endian::native_to_little(sendSegmentId);
	memcpy(data + 4, &sendSegmentIdLE, 4);
	data[12] = flags;
	uint16_t payloadSizeLE = boost::endian::native_to_little(payloadSize);
	memcpy(data + 14, &payloadSizeLE, 2);
	memcpy(data + 16, payload, payloadSize);

	lock.lock();
	if (closed)
		return;

	if (shutdownFlags & SHUTDOWN_SEND)
	{
		completeHandler(ERR_OPERATION_FAILURE);
		return;
	}
	if (flags & FIN)
		shutdownFlags |= SHUTDOWN_SEND;
	if (flags & RST)
		shutdownFlags |= SHUTDOWN_COMPLETE;
	if (sendSegmentId - sendLaskAck_ > sendWindow_)
	{
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
				if (closed)
					return;
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
	if (closed)
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

void LoadBalancingManager::VirtualConnection::DoSendSegment(const std::shared_ptr<Connection> &connection)
{
	std::unique_lock<std::recursive_mutex> lock(mutex_);
	if (closed)
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

	uint32_t ackLE = boost::endian::native_to_little(receiveSegmentIdComplete_);
	assert(sendingSegment->data.size() >= 16);
	memcpy(sendingSegment->data.data() + 8, &ackLE, 4);
	sendingSegment->data[13] = (uint8_t)(std::extent<decltype(receiveSegments_)>::value - (receiveSegmentIdComplete_ - receiveSegmentOffset_));

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
	if (closed)
		return;
	if (sendingSegment->state != SendSegment::SENT || sendingSegment->tryCount != tryCount) //Prevents re-retransmission
		return;
	sendingSegment->state = SendSegment::READY;
	sendingSegment->retryTimer.cancel();
	lock.unlock();
	BeginSendSegment();
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
	if (closed)
		return;
	if (shutdownFlags & SHUTDOWN_RECEIVE)
	{
		if (flags & RST) //Process only RST after SHUTDOWN_RECEIVE is set (FIN received)
		{
			shutdownFlags |= SHUTDOWN_COMPLETE;
			ShutdownCheck();
			return;
		}
		if (!(flags & ACK) && !inQueue_) //Other things are discarded, just send an ACK if needed
		{
			inQueue_ = true;
			lock.unlock();
			parent_.AppendPendingSendSegment(virtualConnectionId_);
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
				shutdownFlags |= SHUTDOWN_SENT;
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
		shutdownFlags |= SHUTDOWN_COMPLETE;
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
		//Reassemble
		size_t segmentPosition = seq - receiveSegmentOffset_;
		if (segmentPosition < kMaxWindowSize)
		{
			auto &receiveSegment = receiveSegments_[segmentPosition];
			if (receiveSegment.first)
			{
				if (receiveSegment.second.size() != size)
				{
					lock.unlock();
					Reset();
					return;
				}
			}
			else
			{
				receiveSegment.first = true;
				receiveSegments_->second.assign(data, data + size);
				if (segmentPosition + 1 > receiveSegmentCount_)
					receiveSegmentCount_ = segmentPosition + 1;

				uint32_t i = 0;
				for (; i < receiveSegmentCount_; ++i)
					if (!receiveSegments_[i].first)
						break;
				receiveSegmentIdComplete_ = receiveSegmentOffset_ + i - 1;
				if (receiveCallback_ && i > 0)
				{
					receiveCallback_(0);
					receiveCallback_ = nullptr;
				}
			}
		}
	}

	if (ackIsValid) //Valid ACK received, send queue and send window updated, check send callback
	{
		if (sendCallback_ && sendSegmentIdPending_ - sendLaskAck_ <= sendWindow_)
		{
			sendCallback_(0);
			sendCallback_ = nullptr;
		}
	}
	if (needAck && !inQueue_) //Send an ACK if needed
	{
		inQueue_ = true;
		lock.unlock();
		parent_.AppendPendingSendSegment(virtualConnectionId_);
	}
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
	virtualConnection->DoSendSegment(connection);
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
			//TODO: make corresponding vConn and send RST
			return;
		}
		//TODO: make corresponding vConn
		generalLock.unlock();
	}
	else
	{
		virtualConnection = itr->second;
		generalLock.unlock();
	}
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
