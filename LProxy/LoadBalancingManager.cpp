#include "pch.h"
#include "LoadBalancingManager.h"

/*
VConnID 4b 0
Seq     4b 4
Ack     4b 8
Flags   2b 12
Wnd     2b 14
Len     2b 16
*/

template <typename T, typename ...TArgs>
inline static void SafeCallback(T &callback, TArgs &&...args)
{
	T func = std::move(callback);
	callback = nullptr;
	func(std::forward<TArgs>(args)...);
}

LoadBalancingManager::LoopInteger LoadBalancingManager::VirtualConnection::StreamWindowBuffer::MaxReadSegmentEnd(LoopInteger segmentBegin, size_t bufferSize) const
{
	if (specialBits_ & EOS_BIT)
		return segmentBegin;

	LoopInteger windowBegin = WindowBegin();
	LoopInteger dataBegin = windowBegin + (specialBits_ & START_BIT ? 1 : 0);
	LoopInteger dataEnd = dataBegin + DataSize();
	LoopInteger windowEnd = dataEnd + (specialBits_ & STOP_BIT ? 1 : 0);

	if (segmentBegin < windowBegin)
		return segmentBegin;
	if (segmentBegin >= windowEnd)
		return segmentBegin;

	if (segmentBegin < dataBegin)
		segmentBegin = dataBegin;
	LoopInteger segmentEnd = segmentBegin + bufferSize;
	if (segmentEnd >= dataEnd)
		return windowEnd;
	return segmentEnd;
}

void LoadBalancingManager::VirtualConnection::StreamWindowBuffer::Reset(LoopInteger streamBegin)
{
	streamOffset_ = streamBegin;
	bufferFrontBegin_ = 0;
	bufferBackEnd_ = kBlockSize;
	specialBits_ = START_BIT;
}

void LoadBalancingManager::VirtualConnection::StreamWindowBuffer::Stop()
{
	specialBits_ |= STOP_BIT;
}

void LoadBalancingManager::VirtualConnection::StreamWindowBuffer::StopForce()
{
	specialBits_ = EOS_BIT;
}

LoadBalancingManager::LoopInteger LoadBalancingManager::VirtualConnection::StreamWindowBuffer::Progress(LoopInteger streamPosition)
{
	if (specialBits_ & EOS_BIT)
		return streamOffset_;
	if (streamPosition <= streamOffset_)
		return streamOffset_;

	if (specialBits_ & START_BIT)
	{
		specialBits_ &= ~START_BIT;
		streamOffset_ += 1;
		if (streamPosition == streamOffset_)
			return streamPosition;
	}
	auto blockIndex = BlockIndex(streamPosition - streamOffset_);
	if (BlockIndexNotOverflow(blockIndex))
	{
		assert(kBlockSize * blockIndex.first + blockIndex.second - bufferFrontBegin_ == streamPosition - streamOffset_);
		buffers_.erase(buffers_.begin(), buffers_.begin() + blockIndex.first);
		bufferFrontBegin_ = blockIndex.second;
		streamOffset_ = streamPosition;
	}
	else
	{
		streamOffset_ += DataSize();
		buffers_.clear();
		bufferFrontBegin_ = 0;
		bufferBackEnd_ = kBlockSize;

		if (streamPosition != streamOffset_ && (specialBits_ & STOP_BIT))
		{
			specialBits_ &= ~STOP_BIT;
			streamOffset_ += 1;
			specialBits_ |= EOS_BIT;
		}
	}
	return streamOffset_;
}

LoadBalancingManager::LoopInteger LoadBalancingManager::VirtualConnection::StreamWindowBuffer::Reserve(LoopInteger streamPosition)
{
	if (specialBits_ & EOS_BIT)
		return streamOffset_;
	LoopInteger streamDataOffset = streamOffset_ + (specialBits_ & START_BIT ? 1 : 0);
	if (streamPosition <= streamDataOffset)
		return streamDataOffset;

	auto blockIndexLastByte = BlockIndex(streamPosition - streamDataOffset - 1);
	if (BlockIndexNotOverflow(blockIndexLastByte))
	{
		return streamPosition;
	}
	else if (specialBits_ & STOP_BIT)
	{
		return streamDataOffset + DataSize();
	}
	else if (blockIndexLastByte.first < kMaxBlockCount)
	{
		buffers_.resize(blockIndexLastByte.first + 1);
		bufferBackEnd_ = blockIndexLastByte.second + 1;
		return streamPosition;
	}
	else
	{
		buffers_.resize(kMaxBlockCount);
		bufferBackEnd_ = kBlockSize;
		return streamDataOffset + DataSize();
	}
}

size_t LoadBalancingManager::VirtualConnection::StreamWindowBuffer::Append(const char *src, size_t srcSize)
{
	if (specialBits_ & (EOS_BIT | STOP_BIT))
		return 0;

	size_t srcSizeOrigin = srcSize;
	if (bufferBackEnd_ < kBlockSize)
	{
		size_t copying = std::min(kBlockSize - bufferBackEnd_, srcSize);
		memcpy(buffers_.back().data + bufferBackEnd_, src, copying);
		bufferBackEnd_ += copying;
		src += copying;
		srcSize -= copying;
	}
	while (srcSize > 0 && buffers_.size() < kMaxBlockCount)
	{
		buffers_.emplace_back();
		size_t copying = std::min(kBlockSize, srcSize);
		memcpy(buffers_.back().data, src, copying);
		bufferBackEnd_ = copying;
		src += copying;
		srcSize -= copying;
	}
	return srcSizeOrigin - srcSize;
}

size_t LoadBalancingManager::VirtualConnection::StreamWindowBuffer::Consume(char *dst, size_t dstSize, uint8_t &specialBits, LoopInteger stopAt)
{
	if (specialBits_ & EOS_BIT)
	{
		specialBits = EOS_BIT;
		return 0;
	}
	specialBits = 0;
	if (stopAt <= streamOffset_)
		return 0;
	if (specialBits_ & START_BIT)
	{
		specialBits |= START_BIT;
		specialBits_ &= ~START_BIT;
		streamOffset_ += 1;
		if (stopAt == streamOffset_)
			return 0;
	}
	auto blockIndex = BlockIndex(stopAt - streamOffset_);
	size_t dstSizeOrigin = dstSize;
	if (BlockIndexNotOverflow(blockIndex))
	{
		while (blockIndex.first > 0 && dstSize > 0)
		{
			if (kBlockSize - bufferFrontBegin_ <= dstSize)
			{
				size_t copying = kBlockSize - bufferFrontBegin_;
				memcpy(dst, buffers_.front().data + bufferFrontBegin_, copying);
				buffers_.pop_front();
				--blockIndex.first;
				bufferFrontBegin_ = 0;
				dst += copying;
				dstSize -= copying;
			}
			else
			{
				size_t copying = dstSize;
				memcpy(dst, buffers_.front().data + bufferFrontBegin_, copying);
				bufferFrontBegin_ += copying;
				dst += copying;
				dstSize = 0;
			}
		}
		if (dstSize > 0)
		{
			size_t copying = std::min(dstSize, blockIndex.second - bufferFrontBegin_);
			memcpy(dst, buffers_.front().data + bufferFrontBegin_, copying);
			bufferFrontBegin_ += copying;
			dst += copying;
			dstSize -= copying;
		}
		streamOffset_ += dstSizeOrigin - dstSize;
	}
	else
	{
		while (buffers_.size() > 1 && dstSize > 0)
		{
			if (kBlockSize - bufferFrontBegin_ <= dstSize)
			{
				size_t copying = kBlockSize - bufferFrontBegin_;
				memcpy(dst, buffers_.front().data + bufferFrontBegin_, copying);
				buffers_.pop_front();
				bufferFrontBegin_ = 0;
				dst += copying;
				dstSize -= copying;
			}
			else
			{
				size_t copying = dstSize;
				memcpy(dst, buffers_.front().data + bufferFrontBegin_, copying);
				bufferFrontBegin_ += copying;
				dst += copying;
				dstSize = 0;
			}
		}
		if (!buffers_.empty() && dstSize > 0)
		{
			assert(buffers_.size() == 1);
			if (bufferBackEnd_ - bufferFrontBegin_ <= dstSize)
			{
				size_t copying = bufferBackEnd_ - bufferFrontBegin_;
				memcpy(dst, buffers_.front().data + bufferFrontBegin_, copying);
				buffers_.pop_front();
				bufferFrontBegin_ = 0;
				bufferBackEnd_ = kBlockSize;
				dst += copying;
				dstSize -= copying;
			}
			else
			{
				size_t copying = dstSize;
				memcpy(dst, buffers_.front().data + bufferFrontBegin_, copying);
				bufferFrontBegin_ += copying;
				dst += copying;
				dstSize = 0;
			}
		}
		streamOffset_ += dstSizeOrigin - dstSize;
		if (buffers_.empty() && (specialBits_ & STOP_BIT))
		{
			specialBits |= STOP_BIT;
			specialBits_ &= ~STOP_BIT;
			streamOffset_ += 1;
			specialBits_ |= EOS_BIT;
		}
	}
	return dstSizeOrigin - dstSize;
}

size_t LoadBalancingManager::VirtualConnection::StreamWindowBuffer::CopyFrom(LoopInteger dstStreamPosition, const char *src, size_t srcSize)
{
	if (specialBits_ & EOS_BIT)
		return 0;
	LoopInteger streamDataOffset = streamOffset_ + (specialBits_ & START_BIT ? 1 : 0);
	if (dstStreamPosition < streamDataOffset)
	{
		if (streamDataOffset - dstStreamPosition > 0x20000000) // Seriously out of range
			throw std::out_of_range("StreamWindowBuffer::CopyFrom: dstStreamPosition out of range");
		uint32_t skipSize = streamDataOffset - dstStreamPosition;
		if (srcSize <= skipSize)
			return srcSize;
		dstStreamPosition = streamDataOffset;
		src += skipSize;
		srcSize -= skipSize;
	}
	auto blockIndex = BlockIndex(dstStreamPosition - streamDataOffset);
	if (!BlockIndexNotOverflow(blockIndex))
	{
		if (dstStreamPosition - streamDataOffset == DataSize())
			return 0;
		throw std::out_of_range("StreamWindowBuffer::CopyFrom: dstStreamPosition out of range");
	}

	size_t srcSizeOrigin = srcSize;
	auto bufferItr = buffers_.begin() + blockIndex.first, bufferItrEnd = --buffers_.end();
	while (bufferItr != bufferItrEnd && srcSize > 0)
	{
		size_t copying = std::min(kBlockSize - blockIndex.second, srcSize);
		memcpy(bufferItr->data + blockIndex.second, src, copying);
		++bufferItr;
		blockIndex.second = 0;
		src += copying;
		srcSize -= copying;
	}
	if (srcSize > 0)
	{
		size_t copying = std::min(bufferBackEnd_ - blockIndex.second, srcSize);
		memcpy(bufferItr->data + blockIndex.second, src, copying);
		src += copying;
		srcSize -= copying;
	}
	return srcSizeOrigin - srcSize;
}

size_t LoadBalancingManager::VirtualConnection::StreamWindowBuffer::CopyTo(LoopInteger srcStreamPosition, char *dst, size_t dstSize, uint8_t &specialBits) const
{
	if (specialBits_ & EOS_BIT)
	{
		specialBits = EOS_BIT;
		return 0;
	}
	specialBits = 0;
	LoopInteger streamDataOffset = streamOffset_;
	if (specialBits_ & START_BIT)
	{
		if (srcStreamPosition == streamDataOffset)
			specialBits |= START_BIT;
		else
			streamDataOffset += 1;
	}
	if (srcStreamPosition < streamDataOffset)
		throw std::out_of_range("StreamWindowBuffer::CopyTo: srcStreamPosition out of range");
	auto blockIndex = BlockIndex(srcStreamPosition - streamDataOffset);
	if (!BlockIndexNotOverflow(blockIndex))
	{
		if (srcStreamPosition - streamDataOffset == DataSize())
		{
			if (specialBits_ & STOP_BIT)
				specialBits |= STOP_BIT;
			return 0;
		}
		throw std::out_of_range("StreamWindowBuffer::CopyTo: srcStreamPosition out of range");
	}

	size_t dstSizeOrigin = dstSize;
	auto bufferItr = buffers_.begin() + blockIndex.first, bufferItrEnd = --buffers_.end();
	while (bufferItr != bufferItrEnd && dstSize > 0)
	{
		size_t copying = std::min(dstSize, kBlockSize - blockIndex.second);
		memcpy(dst, bufferItr->data + blockIndex.second, copying);
		++bufferItr;
		blockIndex.second = 0;
		dst += copying;
		dstSize -= copying;
	}
	if (dstSize > 0)
	{
		size_t copying = std::min(dstSize, bufferBackEnd_ - blockIndex.second);
		memcpy(dst, bufferItr->data + blockIndex.second, copying);
		dst += copying;
		dstSize -= copying;
		if ((specialBits_ & STOP_BIT) && copying == bufferBackEnd_ - blockIndex.second)
			specialBits |= STOP_BIT;
	}
	return dstSizeOrigin - dstSize;
}

void LoadBalancingManager::VirtualConnection::OnSegmentSuccess()
{
	if (sendCongestionWindow_ > 0x10000)
		sendCongestionWindow_ += 0x100;
	else
		sendCongestionWindow_ *= 2;
	//std::cout << virtualConnectionId_ << " send window increasing to: " << SendWindowSize() << std::endl;
}

void LoadBalancingManager::VirtualConnection::OnSegmentFailure()
{
	sendCongestionWindow_ /= 2;
	if (sendCongestionWindow_ == 0)
		sendCongestionWindow_ = 1;
	//std::cout << virtualConnectionId_ << " send window decreasing to: " << SendWindowSize() << std::endl;
}

uint32_t LoadBalancingManager::VirtualConnection::SendWindowSize()
{
	//TODO: Better way to determine RTT?
	if (std::chrono::steady_clock::now() - sendLastAckReceivedTime_ > std::chrono::milliseconds(200))
		return std::min(std::max<uint32_t>(sendSlidingWindow_, 16), sendCongestionWindow_ * 0x100);
	return sendCongestionWindow_;
}

uint32_t LoadBalancingManager::VirtualConnection::SendAckValue()
{
	if (receiveSegmentsOk_.empty())
		return receiveBuffer_.WindowEnd().value();
	if (receiveSegmentsOk_.front().segmentBegin <= receiveBuffer_.WindowBegin())
		return receiveSegmentsOk_.front().segmentEnd.value();
	return receiveBuffer_.WindowBegin().value();
}

void LoadBalancingManager::VirtualConnection::AsyncStart(null_callback &&completeHandler)
{
	std::unique_lock<std::recursive_mutex> lock(mutex_);
	sendBuffer_.Reset(0);
	lock.unlock();
	BeginSendSegmentForce();
	completeHandler(0);
}

void LoadBalancingManager::VirtualConnection::AsyncSendData(const const_buffer &buffer, prx_tcp_socket::transfer_callback &&completeHandler)
{
	std::unique_lock<std::recursive_mutex> lock(mutex_);
	if (closed_ || shutdownFlags_ & SHUTDOWN_SEND)
	{
		completeHandler(ERR_OPERATION_FAILURE, 0);
		return;
	}

	if (sendBuffer_.Full() || sendBuffer_.DataSize() >= SendWindowSize())
	{
		std::shared_ptr<prx_tcp_socket::transfer_callback> callback = std::make_shared<prx_tcp_socket::transfer_callback>(completeHandler);
		sendCallback_ = [this, buffer, callback](error_code err)
		{
			if (err)
			{
				(*callback)(err, 0);
				return;
			}
			ioContext_.post([this, self = shared_from_this(), buffer, callback]()
			{
				AsyncSendData(buffer, std::move(*callback));
			});
		};
	}
	else
	{
		size_t transferred = sendBuffer_.Append(buffer.data(), buffer.size());
		lock.unlock();
		BeginSendSegment();
		completeHandler(0, transferred);
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
		LoopInteger sendSegmentBegin = sendBuffer_.WindowBegin(), sendSegmentEnd;
		LoopInteger maxSendSegmentEnd = sendBuffer_.MaxReadSegmentEnd(sendSegmentBegin, SendWindowSize());
		for (const auto &p : sendSegmentsInFlight_)
		{
			sendSegmentEnd = p->segmentBegin;
			assert(sendSegmentEnd >= sendSegmentBegin);
			if (sendSegmentEnd >= maxSendSegmentEnd)
				break;
			if (sendSegmentEnd != sendSegmentBegin)
			{
				dataReady = true;
				break;
			}
			sendSegmentBegin = p->segmentEnd;
		}
		if (!dataReady)
		{
			sendSegmentEnd = maxSendSegmentEnd;
			if (sendSegmentEnd <= sendSegmentBegin)
				return;
		}
		inQueue_ = true;
		lock.unlock();
		parent_.AppendPendingSendSegment(virtualConnectionId_);
	}
}

void LoadBalancingManager::VirtualConnection::BeginSendSegmentForce()
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

	bool dataReady = false;
	LoopInteger sendSegmentBegin = sendBuffer_.WindowBegin(), sendSegmentEnd;
	LoopInteger maxSendSegmentEnd = sendBuffer_.MaxReadSegmentEnd(sendSegmentBegin, SendWindowSize());
	for (const auto &p : sendSegmentsInFlight_)
	{
		sendSegmentEnd = p->segmentBegin;
		assert(sendSegmentEnd >= sendSegmentBegin);
		if (sendSegmentEnd >= maxSendSegmentEnd)
			break;
		if (sendSegmentEnd != sendSegmentBegin)
		{
			dataReady = true;
			break;
		}
		sendSegmentBegin = p->segmentEnd;
	}
	if (!dataReady)
	{
		sendSegmentEnd = maxSendSegmentEnd;
		if (sendSegmentEnd > sendSegmentBegin)
			dataReady = true;
	}
	if (!dataReady)
	{
		sendSegmentBegin = maxSendSegmentEnd;
	}

	//Make send segment

	size_t dataSizeReserved = 0;
	if (dataReady)
	{
		if (sendSegmentEnd - sendSegmentBegin > kMaxSegmentSize)
			dataSizeReserved = kMaxSegmentSize;
		else
			dataSizeReserved = sendSegmentEnd - sendSegmentBegin;
	}
	std::vector<char> segmentData;
	segmentData.resize(kHeaderSize + dataSizeReserved);
	memcpy(segmentData.data(), &virtualConnectionId_, 4);
	uint32_t segLE = boost::endian::native_to_little(sendSegmentBegin.value());
	memcpy(segmentData.data() + 4, &segLE, 4);
	uint32_t ackLE = boost::endian::native_to_little(SendAckValue());
	memcpy(segmentData.data() + 8, &ackLE, 4);
	uint16_t wndLE = boost::endian::native_to_little((uint16_t)(receiveBuffer_.DataSize() > 0xFFFF ? 0 : 0xFFFF - receiveBuffer_.DataSize()));
	memcpy(segmentData.data() + 14, &wndLE, 2);

	uint16_t flags = 0;
	if (dataReady)
	{
		uint8_t specialBits, specialBitCounter = 0;
		size_t dataSizeCopied = sendBuffer_.CopyTo(sendSegmentBegin, segmentData.data() + kHeaderSize, dataSizeReserved, specialBits);
		assert(dataSizeCopied <= dataSizeReserved);
		assert(!(specialBits & StreamWindowBuffer::EOS_BIT));
		if (specialBits & StreamWindowBuffer::START_BIT)
			flags |= SYN, ++specialBitCounter;
		if (specialBits & StreamWindowBuffer::STOP_BIT)
			flags |= FIN, ++specialBitCounter;
		if (dataSizeCopied + specialBitCounter > sendSegmentEnd - sendSegmentBegin)
		{
			size_t erasing = std::min(dataSizeCopied, (dataSizeCopied + specialBitCounter) - (sendSegmentEnd - sendSegmentBegin));
			dataSizeCopied -= erasing;
		}
		assert(dataSizeCopied > 0 || flags != 0);
		segmentData.resize(kHeaderSize + dataSizeCopied);
		uint16_t flagsLE = boost::endian::native_to_little(flags);
		memcpy(segmentData.data() + 12, &flagsLE, 2);
		uint16_t lenLE = boost::endian::native_to_little((uint16_t)dataSizeCopied);
		memcpy(segmentData.data() + 16, &lenLE, 2);
		sendSegmentEnd = sendSegmentBegin + dataSizeCopied + specialBitCounter;
		//std::cout << "send " << virtualConnectionId_ << ' ' << segLE << ' ' << ackLE << ' ' << flagsLE << ' ' << wndLE << ' ' << lenLE << std::endl;
	}
	else
	{
		//ACK or RST
		if (sendBuffer_.EndOfStream())
			flags |= RST;
		else
			flags |= ACK;
		uint16_t flagsLE = boost::endian::native_to_little(flags);
		memcpy(segmentData.data() + 12, &flagsLE, 2);
		uint16_t lenLE = 0;
		memcpy(segmentData.data() + 16, &lenLE, 2);
		sendSegmentEnd = sendSegmentBegin;
		//std::cout << "send " << virtualConnectionId_ << ' ' << segLE << ' ' << ackLE << ' ' << flagsLE << ' ' << wndLE << ' ' << lenLE << std::endl;
	}

	std::shared_ptr<SendSegment> sendingSegment = std::make_shared<SendSegment>(ioContext_, sendSegmentBegin, sendSegmentEnd, std::move(segmentData), !dataReady);

	sendingSegment->state = SendSegment::INFLIGHT;
	if (!sendingSegment->isAcknowledgement) //ACKs don't need acknowledgement and retransmission
	{
		sendingSegment->retryTimer.expires_after(std::chrono::milliseconds(connection->RTT() * 2));
		sendingSegment->retryTimer.async_wait([this, self = shared_from_this(), sendingSegment](const boost::system::error_code &ec)
		{
			if (!ec)
			{
				RetrySendSegment(sendingSegment);
			}
		});
		auto itr = sendSegmentsInFlight_.begin();
		for (auto itrEnd = sendSegmentsInFlight_.end(); itr != itrEnd; ++itr)
		{
			if (sendingSegment->segmentEnd <= (*itr)->segmentBegin)
			{
				assert(itr == sendSegmentsInFlight_.begin() || (*(itr - 1))->segmentEnd <= sendingSegment->segmentBegin);
				break;
			}
		}
		sendSegmentsInFlight_.insert(itr, sendingSegment);
	}

	lock.unlock();
	connection->Socket()->async_write(const_buffer(sendingSegment->data),
		[this, self = shared_from_this(), connection, sendingSegment](error_code err)
	{
		if (err)
		{
			connection->SetConnectionFailed();
			connection->ReleaseConnection();
			RetrySendSegment(sendingSegment);
		}
		else
		{
			connection->ReleaseConnection();
		}
	});
	if (flags & RST) // RST is sent
	{
		lock.lock();
		if (closed_)
			return;
		ShutdownCheck();
		return;
	}
	if (dataReady) // Not empty, more data may present
		BeginSendSegment();
}

void LoadBalancingManager::VirtualConnection::RetrySendSegment(const std::shared_ptr<SendSegment> &sendingSegment)
{
	if (sendingSegment->isAcknowledgement) //ACKs don't need retransmission
		return;
	std::unique_lock<std::recursive_mutex> lock(mutex_);
	if (closed_)
		return;
	if (sendingSegment->state != SendSegment::INFLIGHT) //Prevents re-retransmission
		return;
	OnSegmentFailure();
	sendingSegment->state = SendSegment::READY;
	sendingSegment->retryTimer.cancel();
	lock.unlock();
	BeginSendSegment();
}

void LoadBalancingManager::VirtualConnection::AsyncReceiveData(const mutable_buffer &buffer, prx_tcp_socket::transfer_callback &&completeHandler)
{
	std::unique_lock<std::recursive_mutex> lock(mutex_);
	if (closed_ || (shutdownFlags_ & SHUTDOWN_RECEIVE))
	{
		lock.unlock();
		completeHandler(ERR_OPERATION_FAILURE, 0);
		return;
	}
	if (receiveBuffer_.Empty())
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
		BeginSendSegmentForce();
}

void LoadBalancingManager::VirtualConnection::OnReceiveSegment(const char *data, size_t size)
{
	uint32_t seq, ack;
	memcpy(&seq, data + 4, 4);
	boost::endian::little_to_native_inplace(seq);
	memcpy(&ack, data + 8, 4);
	boost::endian::little_to_native_inplace(ack);
	uint16_t flags, wnd;
	memcpy(&flags, data + 12, 2);
	boost::endian::little_to_native_inplace(flags);
	memcpy(&wnd, data + 14, 2);
	boost::endian::little_to_native_inplace(wnd);
	//std::cout << "recv " << virtualConnectionId_ << ' ' << seq << ' ' << ack << ' ' << flags << ' ' << wnd << ' ' << size - kHeaderSize << std::endl;

	std::unique_lock<std::recursive_mutex> lock(mutex_);
	if (closed_)
		return;

	bool ackIsValid = (LoopInteger(ack) >= sendBuffer_.WindowBegin() && sendBuffer_.WindowEnd() >= LoopInteger(ack));
	if (ackIsValid) //Process valid ACKs even if SHUTDOWN_RECEIVE
	{
		auto itr = sendSegmentsInFlight_.begin(), itrEnd = sendSegmentsInFlight_.end();
		for (; itr != itrEnd; ++itr)
		{
			const auto &segment = *itr;
			if (LoopInteger(ack) <= segment->segmentBegin)
				break;
			if (segment->state == SendSegment::INFLIGHT)
				OnSegmentSuccess();
			segment->state = SendSegment::ACKNOWLEDGED;
			segment->retryTimer.cancel();
		}
		sendSegmentsInFlight_.erase(sendSegmentsInFlight_.begin(), itr);
		sendBuffer_.Progress(ack);
		if (sendBuffer_.EndOfStream())
		{
			shutdownFlags_ |= SHUTDOWN_SENT;
			ShutdownCheck();
		}
		sendSlidingWindow_ = wnd;
		sendLastAckReceivedTime_ = std::chrono::steady_clock::now();
	}

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
			BeginSendSegmentForce();
		}
		return;
	}

	if (!ackIsValid) //Check if ack is seriously out of range
	{
		if (ack - sendBuffer_.WindowBegin().value() >= 0x20000000 && ack - sendBuffer_.WindowBegin().value() < 0xE0000000)
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
		LoopInteger receiveSegmentBegin = seq;
		LoopInteger receiveDataBegin = receiveSegmentBegin + (flags & SYN ? 1 : 0);
		receiveBuffer_.Reserve(receiveDataBegin + size - kHeaderSize);
		bool copyOk = false;
		size_t copied = 0;
		try
		{
			copied = receiveBuffer_.CopyFrom(receiveDataBegin, data + kHeaderSize, size - kHeaderSize);
			copyOk = true;
		}
		catch (...) {}
		if (copyOk)
		{
			LoopInteger receiveDataEnd = receiveDataBegin + copied;
			LoopInteger receiveSegmentEnd = receiveDataEnd;
			if ((flags & FIN) && copied == size - kHeaderSize)
			{
				receiveBuffer_.Stop();
				receiveSegmentEnd += 1;
			}

			if (receiveSegmentBegin < receiveBuffer_.WindowBegin())
				receiveSegmentBegin = receiveBuffer_.WindowBegin();
			if (receiveSegmentEnd > receiveBuffer_.WindowEnd())
				receiveSegmentEnd = receiveBuffer_.WindowEnd();
			if (receiveSegmentBegin < receiveSegmentEnd) //Valid segment?
			{
				auto itr = receiveSegmentsOk_.begin(), itrEnd = receiveSegmentsOk_.end();
				for (; itr != itrEnd; ++itr)
					if (receiveSegmentEnd <= itr->segmentEnd)
						break;
				if (itr != itrEnd && receiveSegmentEnd >= itr->segmentBegin) //Overlap?
					itr->segmentBegin = std::min(itr->segmentBegin, receiveSegmentBegin);
				else
					itr = receiveSegmentsOk_.insert(itr, ReceiveSegment(receiveSegmentBegin.value(), receiveSegmentEnd.value()));
				if (itr != receiveSegmentsOk_.begin())
				{
					auto itrPrev = itr;
					--itrPrev;
					if (itr->segmentBegin >= itrPrev->segmentEnd) //Overlap?
					{
						itrPrev->segmentEnd = std::max(itrPrev->segmentEnd, itr->segmentEnd);
						//TODO: Try avoid unnecessary insert
						receiveSegmentsOk_.erase(itr);
					}
				}

				//Check if reassembled data at head
				if (receiveSegmentsOk_.front().segmentBegin <= receiveBuffer_.WindowBegin())
				{
					//Check FIN
					if (receiveBuffer_.Stopped() && receiveSegmentsOk_.front().segmentEnd >= receiveBuffer_.WindowEnd())
					{
						//FIN appeared, set SHUTDOWN_RECEIVE
						shutdownFlags_ |= SHUTDOWN_RECEIVE;
						ShutdownCheck();
						//if (!(shutdownFlags_ & SHUTDOWN_SEND)) //Auto stop send
						//	ioContext_.post([this, self = shared_from_this()]() { ShutdownSend(); });
					}
					if (receiveCallback_)
					{
						SafeCallback(receiveCallback_, 0);
					}
				}
			}
		}
	}

	if (ackIsValid) //Valid ACK received, send queue and send window updated, check send callback and send queue
	{
		if (sendCallback_ && !(sendBuffer_.Full() || sendBuffer_.DataSize() >= SendWindowSize()))
		{
			SafeCallback(sendCallback_, 0);
		}
		lock.unlock();
		BeginSendSegment();
	}
	if (needAck) //Send an ACK if needed
	{
		if (lock.owns_lock())
			lock.unlock();
		BeginSendSegmentForce();
	}
}

bool LoadBalancingManager::VirtualConnection::ConsumeReceiveSegment(char *dst, size_t dstSize, size_t &transferred)
{
	transferred = 0;
	if (receiveSegmentsOk_.empty())
	{
		uint8_t specialBits;
		transferred = receiveBuffer_.Consume(dst, dstSize, specialBits, receiveBuffer_.WindowEnd());
		return transferred != 0 || specialBits != 0;
	}
	if (receiveSegmentsOk_.front().segmentBegin <= receiveBuffer_.WindowBegin())
	{
		uint8_t specialBits;
		transferred = receiveBuffer_.Consume(dst, dstSize, specialBits, receiveSegmentsOk_.front().segmentEnd);
		receiveSegmentsOk_.front().segmentBegin = receiveBuffer_.WindowBegin();
		if (receiveSegmentsOk_.front().segmentBegin >= receiveSegmentsOk_.front().segmentEnd)
			receiveSegmentsOk_.pop_front();
		return transferred != 0 || specialBits != 0;
	}
	return false;
}

void LoadBalancingManager::VirtualConnection::ShutdownSend()
{
	std::unique_lock<std::recursive_mutex> lock(mutex_);
	if (sendCallback_)
	{
		SafeCallback(sendCallback_, ERR_OPERATION_FAILURE);
	}
	sendBuffer_.Stop();
	shutdownFlags_ |= SHUTDOWN_SEND;
	lock.unlock();
	BeginSendSegmentForce();
}

void LoadBalancingManager::VirtualConnection::ShutdownReceive()
{
	std::unique_lock<std::recursive_mutex> lock(mutex_);
	shutdownFlags_ |= SHUTDOWN_RECEIVE;
	ShutdownCheck();
	lock.unlock();
}

void LoadBalancingManager::VirtualConnection::Reset()
{
	std::unique_lock<std::recursive_mutex> lock(mutex_);
	if (sendCallback_)
	{
		SafeCallback(sendCallback_, ERR_OPERATION_FAILURE);
	}
	sendBuffer_.StopForce();
	lock.unlock();
	BeginSendSegmentForce();
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

void LoadBalancingManager::AsyncSend(uint32_t vConnId, const const_buffer &buffer, prx_tcp_socket::transfer_callback &&completeHandler)
{
	std::unique_lock<std::recursive_mutex> generalLock(generalMutex_);
	auto itr = virtualConnections_.find(vConnId);
	if (itr == virtualConnections_.end())
	{
		generalLock.unlock();
		completeHandler(ERR_OPERATION_FAILURE, 0);
		return;
	}
	std::shared_ptr<VirtualConnection> virtualConnection = itr->second;
	generalLock.unlock();
	virtualConnection->AsyncSendData(buffer, std::move(completeHandler));
}

void LoadBalancingManager::AsyncReceive(uint32_t vConnId, const mutable_buffer &buffer, prx_tcp_socket::transfer_callback &&completeHandler)
{
	std::unique_lock<std::recursive_mutex> generalLock(generalMutex_);
	auto itr = virtualConnections_.find(vConnId);
	if (itr == virtualConnections_.end())
	{
		generalLock.unlock();
		completeHandler(ERR_OPERATION_FAILURE, 0);
		return;
	}
	std::shared_ptr<VirtualConnection> virtualConnection = itr->second;
	generalLock.unlock();
	virtualConnection->AsyncReceiveData(buffer, std::move(completeHandler));
}

void LoadBalancingManager::Shutdown(uint32_t vConnId)
{
	std::unique_lock<std::recursive_mutex> generalLock(generalMutex_);
	auto itr = virtualConnections_.find(vConnId);
	if (itr == virtualConnections_.end())
		return;
	std::shared_ptr<VirtualConnection> virtualConnection = itr->second;
	generalLock.unlock();
	virtualConnection->ShutdownSend();
}

void LoadBalancingManager::NewConnection(size_t index, std::unique_ptr<prx_tcp_socket>&& socket, uint16_t rtt)
{
	std::shared_ptr<BaseConnection> baseConnection = std::make_shared<BaseConnection>(index, std::move(socket), rtt);
	ReceiveSegment(baseConnection);
	ReleaseConnection(std::move(baseConnection), false);
}

void LoadBalancingManager::AppendPendingSendSegment(uint32_t virtualConnectionId)
{
	std::unique_lock<std::recursive_mutex> generalLock(generalMutex_);
	if (!requestQueueSet_.insert(virtualConnectionId).second)
		return;
	bool needDispatch = !idleConnections_.empty();
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
	if (!*connection)
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
	receiveSocket->socket->async_read(mutable_buffer(receiveSocket->receiveBuffer, kHeaderSize),
		[this, receiveSocket](error_code err)
	{
		if (err)
		{
			EndReceiveSegmentWithError(receiveSocket);
			return;
		}
		uint16_t len;
		memcpy(&len, receiveSocket->receiveBuffer + 16, 2);
		boost::endian::little_to_native_inplace(len);
		if (len == 0)
		{
			EndReceiveSegment(receiveSocket, len);
			ReceiveSegment(receiveSocket);
		}
		else
		{
			receiveSocket->socket->async_read(mutable_buffer(receiveSocket->receiveBuffer + kHeaderSize, len),
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
		uint16_t flags;
		memcpy(&flags, receiveSocket->receiveBuffer + 12, 2);
		boost::endian::little_to_native_inplace(flags);
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
	virtualConnection->OnReceiveSegment(receiveSocket->receiveBuffer, kHeaderSize + len);
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
			ioContext_.post([this, receiveSocket]() { OnConnectionReset(receiveSocket->index); });
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
			ioContext_.post([this, connection]() { OnConnectionReset(connection->index); });
		});
		return;
	}
	std::unique_lock<std::recursive_mutex> generalLock(generalMutex_);
	bool needDispatch = !requestQueue_.empty();
	if (!idleConnections_.emplace(conn->index, std::move(conn)).second)
		return;
	if (needDispatch)
	{
		generalLock.unlock();
		DispatchPendingSendSegment();
	}
}
