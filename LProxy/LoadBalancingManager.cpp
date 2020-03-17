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

void LoadBalancingManager::VirtualConnection::AppendSendRequest(uint8_t flags, const char *payload, uint16_t payloadSize, SendRequestCallback &&completeHandler)
{
	if (payloadSize == 0)
		return; //Empty data segment is not allowed
	std::shared_ptr<SendRequest> sendingSegment = std::make_shared<SendRequest>(ioContext_, true);
	sendingSegment->data.resize(16 + payloadSize);
	char *data = sendingSegment->data.data();
	uint32_t virtualConnectionIdLE = boost::endian::native_to_little(virtualConnectionId_);
	memcpy(data, &virtualConnectionIdLE, 4);
	uint32_t sendSegmentIdNextLE = boost::endian::native_to_little(sendSegmentIdNext_++);
	memcpy(data + 4, &sendSegmentIdNextLE, 4);
	data[12] = flags;
	uint16_t payloadSizeLE = boost::endian::native_to_little(payloadSize);
	memcpy(data + 14, &payloadSizeLE, 2);

	std::unique_lock<std::recursive_mutex> lock(mutex_);
	if (closed)
		return;
	if (sendSegments_.size() >= sendWindow_)
	{
		std::shared_ptr<SendRequestCallback> callback = std::make_shared<SendRequestCallback>(completeHandler);
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
				BeginSendRequest();
				(*callback)(0);
			});
		};
	}
	else
	{
		sendSegments_.push_back(std::move(sendingSegment));
		lock.unlock();
		BeginSendRequest();
		completeHandler(0);
	}
}

void LoadBalancingManager::VirtualConnection::BeginSendRequest()
{
	std::unique_lock<std::recursive_mutex> lock(mutex_);
	if (closed)
		return;
	if (!inQueue_)
	{
		bool dataReady = false;
		auto itr = sendSegments_.begin(), itrEnd = sendSegments_.begin() + std::min(sendSegments_.size(), sendWindow_);
		while (!dataReady && itr != itrEnd)
		{
			const auto &sendingSegment = *itr;
			switch (sendingSegment->state)
			{
			case SendRequest::READY:
				//Found, breaking
				dataReady = true;
				break;
			case SendRequest::SENT:
				++itr;
				break;
			case SendRequest::ACKNOWLEDGED: //Shoudn't happen
				assert(false);
			}
		}
		if (!dataReady)
			return;
		inQueue_ = true;
		lock.unlock();
		parent_.AppendPendingSendRequest(virtualConnectionId_);
	}
}

void LoadBalancingManager::VirtualConnection::DoSendRequest(const std::shared_ptr<Connection> &connection)
{
	std::unique_lock<std::recursive_mutex> lock(mutex_);
	if (closed)
		return;
	inQueue_ = false;

	std::shared_ptr<SendRequest> sendingSegment;
	auto itr = sendSegments_.begin(), itrEnd = sendSegments_.begin() + std::min(sendSegments_.size(), sendWindow_);
	while (!sendingSegment && itr != itrEnd)
	{
		sendingSegment = *itr;
		switch (sendingSegment->state)
		{
		case SendRequest::READY:
			//Found, breaking
			break;
		case SendRequest::SENT:
			sendingSegment.reset();
			++itr;
			break;
		case SendRequest::ACKNOWLEDGED: //Shoudn't happen
			assert(false);
		}
	}
	if (!sendingSegment)
	{
		//Make a Pure ACK segment
		sendingSegment = std::make_shared<SendRequest>(ioContext_, true);
		sendingSegment->data.resize(16);
		char *data = sendingSegment->data.data();
		uint32_t virtualConnectionIdLE = boost::endian::native_to_little(virtualConnectionId_);
		memcpy(data, &virtualConnectionIdLE, 4);
		uint32_t sendSegmentIdNextLE = boost::endian::native_to_little(sendSegmentIdNext_++);
		memcpy(data + 4, &sendSegmentIdNextLE, 4);
		data[12] = data[14] = data[15] = 0;
	}

	uint32_t ackLE = boost::endian::native_to_little(receiveSegmentIdComplete_);
	uint8_t wndLE = boost::endian::native_to_little((uint8_t)(std::extent<decltype(receiveSegments_)>::value - receiveSegmentCount_));
	assert(sendingSegment->data.size() >= 16);
	memcpy(sendingSegment->data.data() + 8, &ackLE, 4);
	sendingSegment->data[13] = wndLE;

	sendingSegment->state = SendRequest::SENT;
	++sendingSegment->tryCount;
	if (!sendingSegment->isPureAck) //Pure ACK doesn't need retransmission
	{
		sendingSegment->retryTimer.expires_after(kTimeRetry);
		sendingSegment->retryTimer.async_wait([this, self = shared_from_this(), sendingSegment, tryCount = sendingSegment->tryCount](const boost::system::error_code &ec)
		{
			if (!ec)
				RetrySendRequest(sendingSegment, tryCount);
		});
	}

	lock.unlock();
	connection->AccessConnection()->async_write(const_buffer(sendingSegment->data),
		[this, self = shared_from_this(), connection, sendingSegment, tryCount = sendingSegment->tryCount](error_code err)
	{
		if (err)
		{
			connection->SetConnectionFailed();
			connection->ReleaseConnection();
			RetrySendRequest(sendingSegment, tryCount);
		}
		else
		{
			connection->ReleaseConnection();
		}
	});
	if (!sendingSegment->isPureAck) //Pure ACK only appears when nothing is ready
		BeginSendRequest();
}

void LoadBalancingManager::VirtualConnection::RetrySendRequest(const std::shared_ptr<SendRequest> &sendingSegment, size_t tryCount)
{
	if (sendingSegment->isPureAck) //Pure ACK doesn't need retransmission
		return;
	std::unique_lock<std::recursive_mutex> lock(mutex_);
	if (closed)
		return;
	if (sendingSegment->state != SendRequest::SENT || sendingSegment->tryCount != tryCount)
		return;
	sendingSegment->state = SendRequest::READY;
	sendingSegment->retryTimer.cancel();
	lock.unlock();
	BeginSendRequest();
}

void LoadBalancingManager::AppendPendingSendRequest(uint32_t virtualConnectionId)
{
	std::unique_lock<std::recursive_mutex> generalLock(generalMutex_);
	if (!requestQueueSet_.insert(virtualConnectionId).second)
		return;
	bool needDispatch = requestQueue_.empty() && !idleConnections_.empty();
	requestQueue_.push_back(virtualConnectionId);
	if (needDispatch)
		DispatchPendingSendRequest();
}

void LoadBalancingManager::DispatchPendingSendRequest()
{
	std::unique_lock<std::recursive_mutex> generalLock(generalMutex_);
	if (requestQueue_.empty())
		return;
	if (idleConnections_.empty())
		return;

	std::shared_ptr<Connection> connection = std::make_shared<Connection>(*this);
	if (!connection->AccessConnection())
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
	virtualConnection->DoSendRequest(connection);
}

LoadBalancingManager::BaseConnection LoadBalancingManager::OccupyConnection()
{
	std::lock_guard<std::recursive_mutex> generalLock(generalMutex_);
	if (idleConnections_.empty())
		return BaseConnection();
	auto itr = idleConnections_.begin();
	BaseConnection ret = std::move(itr->second);
	idleConnections_.erase(itr);
	return ret;
}

void LoadBalancingManager::ReleaseConnection(BaseConnection &&conn, bool failed)
{
	if (failed)
	{
		std::shared_ptr<BaseConnection> connection = std::make_shared<BaseConnection>(std::move(conn));
		connection->connection->async_close([this, connection](error_code)
		{
			ioContext_.post([this, connection]() { InitConnection(connection->index); });
		});
		return;
	}
	std::lock_guard<std::recursive_mutex> generalLock(generalMutex_);
	bool needDispatch = !requestQueue_.empty() && idleConnections_.empty();
	idleConnections_.emplace(conn.index, std::move(conn));
	if (needDispatch)
		DispatchPendingSendRequest();
}

void LoadBalancingManager::InitConnection(size_t index)
{
	NewBaseTcpSocket(index,
		[this, index](error_code err, std::unique_ptr<prx_tcp_socket> &&socket)
	{
		if (err)
		{
			InitConnection(index);
			return;
		}
		std::shared_ptr<prx_tcp_socket> shared_socket(std::move(socket));
		BeginReceiveSegment(shared_socket);
		ReleaseConnection(BaseConnection(index, std::move(shared_socket)), false);
	});
}
