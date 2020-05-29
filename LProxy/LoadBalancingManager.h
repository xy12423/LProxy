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

#pragma once

class LoadBalancingManager
{
	enum
	{
		SYN = 0x01,
		FIN = 0x02,
		RST = 0x04,
		ACK = 0x08,
	};

	static constexpr size_t kAcceptQueueMax = 8;
	static constexpr size_t kHeaderSize = 18;

	class LoopInteger
	{
	public:
		LoopInteger() :val_(0) {}
		LoopInteger(uint32_t val) :val_(val) {}
		uint32_t value() const { return val_; }

		template <typename T> LoopInteger operator+(T ropand) const { return LoopInteger(val_ + ropand); }
		uint32_t operator-(const LoopInteger &ropand) const { return val_ - ropand.val_; }
		template <typename T> LoopInteger &operator+=(T ropand) { val_ += ropand; return *this; }
		template <typename T> LoopInteger &operator-=(T ropand) { val_ -= ropand; return *this; }

		bool operator<(const LoopInteger &rhs) const { return (val_ - rhs.val_) & 0x80000000; }
		bool operator>(const LoopInteger &rhs) const { return (rhs.val_ - val_) & 0x80000000; }
		bool operator<=(const LoopInteger &rhs) const { return !((rhs.val_ - val_) & 0x80000000); }
		bool operator>=(const LoopInteger &rhs) const { return !((val_ - rhs.val_) & 0x80000000); }
		bool operator==(const LoopInteger &rhs) const { return val_ == rhs.val_; }
		bool operator!=(const LoopInteger &rhs) const { return val_ != rhs.val_; }
	private:
		uint32_t val_;
	};

	struct BaseConnection
	{
		BaseConnection() = default;
		BaseConnection(size_t idx, std::unique_ptr<prx_tcp_socket> &&soc, uint16_t rtt_ms) :index(idx), socket(std::move(soc)), rtt(rtt_ms) {}
		BaseConnection(const BaseConnection &) = delete;
		BaseConnection(BaseConnection &&) = default;

		size_t index = -1;
		const std::unique_ptr<prx_tcp_socket> socket;
		uint16_t rtt; //In milliseconds

		char receiveBuffer[kHeaderSize + 0x10000];
	};

	struct Connection
	{
	public:
		Connection(LoadBalancingManager &parent_)
			:parent(parent_), connection(parent.OccupyConnection())
		{
		}
		Connection(const Connection &) = delete;
		Connection(Connection &&) = default;
		~Connection() { if (connection) parent.ReleaseConnection(std::move(connection), connectionFailed); }

		operator bool() const { return (bool)connection; }
		prx_tcp_socket *Socket() const { return connection->socket.get(); }
		uint16_t RTT() const { return connection->rtt; }
		void SetConnectionFailed() { connectionFailed = true; }
		void ReleaseConnection() { parent.ReleaseConnection(std::move(connection), connectionFailed); connection.reset(); }
	private:
		LoadBalancingManager &parent;
		std::shared_ptr<BaseConnection> connection;
		bool connectionFailed = false;
	};

	class VirtualConnection : public std::enable_shared_from_this<VirtualConnection>
	{
		class StreamWindowBuffer
		{
			static constexpr size_t kBlockSize = 0x1000, kMaxBlockCount = 0x2000;
			struct StreamWindowBufferBlock
			{
				char data[kBlockSize];
			};
		public:
			enum : unsigned int
			{
				START_BIT = 0x01,
				STOP_BIT  = 0x02,

				EOS_BIT   = 0x04
			};

			bool Empty() const { return buffers_.empty() && (specialBits_ & (START_BIT | STOP_BIT)) == 0; }
			bool Full() const { return buffers_.size() >= kMaxBlockCount; }
			bool Stopped() const { return specialBits_ & STOP_BIT; }
			bool EndOfStream() const { return specialBits_ & EOS_BIT; }

			size_t DataSize() const
			{
				return (buffers_.size() - 1) * kBlockSize - bufferFrontBegin_ + bufferBackEnd_;
			}
			LoopInteger WindowBegin() const { return streamOffset_; }
			size_t WindowSize() const
			{
				size_t windowSize = DataSize();
				if (specialBits_ & START_BIT)
					++windowSize;
				if (specialBits_ & STOP_BIT)
					++windowSize;
				return windowSize;
			}
			LoopInteger WindowEnd() const { return WindowBegin() + WindowSize(); }
			LoopInteger MaxReadSegmentEnd(LoopInteger segmentBegin, size_t bufferSize) const;

			void Reset(LoopInteger streamBegin);
			void Stop();
			void StopForce();

			LoopInteger Progress(LoopInteger streamPosition);
			LoopInteger Reserve(LoopInteger streamPosition);
			size_t Append(const char *src, size_t srcSize);
			size_t Consume(char *dst, size_t dstSize, uint8_t &specialBits, LoopInteger stopAt);
			size_t CopyFrom(LoopInteger dstStreamPosition, const char *src, size_t srcSize);
			size_t CopyTo(LoopInteger srcStreamPosition, char *dst, size_t dstSize, uint8_t &specialBits) const;
		private:
			std::pair<size_t, size_t> BlockIndex(uint32_t streamPositionDiff) const { return std::make_pair((streamPositionDiff + bufferFrontBegin_) / kBlockSize, (streamPositionDiff + bufferFrontBegin_) % kBlockSize); }
			bool BlockIndexNotOverflow(const std::pair<size_t, size_t> &blockIndex) const { return blockIndex.first + 1 < buffers_.size() || (blockIndex.first + 1 == buffers_.size() && blockIndex.second < bufferBackEnd_); }

			std::deque<StreamWindowBufferBlock> buffers_;
			size_t bufferFrontBegin_ = 0, bufferBackEnd_ = kBlockSize;
			LoopInteger streamOffset_ = 0;
			uint8_t specialBits_ = START_BIT;
		};

		using SegmentCallback = null_callback;

		static constexpr uint16_t kTimeRetryMin = 100;
		static constexpr auto kTimeShutdownWait = std::chrono::seconds(10);
		static constexpr size_t kMaxSegmentSize = 4096;

		static constexpr uint16_t timeOut(uint16_t rtt, size_t tryCount)
		{
			return (uint16_t)(std::min(kTimeRetryMin, rtt) * (tryCount <= 4 ? tryCount : (1 << (tryCount - 2))));
		}

		enum : unsigned int
		{
			SHUTDOWN_SEND     = 0x01,
			SHUTDOWN_RECEIVE  = 0x02,
			SHUTDOWN_SENT     = 0x04,
			SHUTDOWN_FORCE    = 0x08,
			SHUTDOWN_BOTH     = SHUTDOWN_SEND | SHUTDOWN_RECEIVE,
			SHUTDOWN_COMPLETE = SHUTDOWN_SEND | SHUTDOWN_RECEIVE | SHUTDOWN_SENT,
			SHUTDOWN_RESET    = SHUTDOWN_COMPLETE | SHUTDOWN_FORCE,
		};

		struct SendSegment
		{
			SendSegment(asio::io_context &ioCtx, LoopInteger segBegin, LoopInteger segEnd, std::vector<char> &&segData, bool isAck)
				:segmentBegin(segBegin), segmentEnd(segEnd), data(std::move(segData)), isAcknowledgement(isAck), retryTimer(ioCtx)
			{
			}

			enum
			{
				READY,
				INFLIGHT,
				ACKNOWLEDGED,
			};

			const LoopInteger segmentBegin, segmentEnd;
			const std::vector<char> data;
			const bool isAcknowledgement;

			uint16_t state = READY;
			boost::asio::steady_timer retryTimer;
		};

		struct ReceiveSegment
		{
			ReceiveSegment(uint32_t segBegin, uint32_t segEnd)
				:segmentBegin(segBegin), segmentEnd(segEnd)
			{
			}

			LoopInteger segmentBegin, segmentEnd;
		};
	public:
		VirtualConnection(uint32_t vConnId, asio::io_context &ioCtx, LoadBalancingManager &parent_)
			:virtualConnectionId_(vConnId), ioContext_(ioCtx), parent_(parent_), shutdownTimer_(ioCtx)
		{
		}
		~VirtualConnection() { if (sendCallback_) sendCallback_(ERR_OPERATION_FAILURE); if (receiveCallback_) receiveCallback_(ERR_OPERATION_FAILURE); }

		uint32_t VirtualConnectionId() const { return virtualConnectionId_; }

		void AsyncStart(null_callback &&completeHandler);

		void AsyncSendData(const const_buffer &buffer, prx_tcp_socket::transfer_callback &&completeHandler);
		void AsyncReceiveData(const mutable_buffer &buffer, prx_tcp_socket::transfer_callback &&completeHandler);

		void OnSendSegment(const std::shared_ptr<Connection> &connection);
		void OnReceiveSegment(const char *data, size_t size);

		void ShutdownSend();
		void ShutdownReceive();
		void Reset();
	private:
		void OnSegmentSuccess();
		void OnSegmentFailure();
		uint32_t SendWindowSize();
		uint32_t SendAckValue();
		void BeginSendSegment();
		void BeginSendSegmentForce();
		void RetrySendSegment(const std::shared_ptr<SendSegment> &sendingSegment);

		//Returns whether receive window is changed
		bool ConsumeReceiveSegment(char *dst, size_t dstSize, size_t &transferred);

		void ShutdownCheck();

		const uint32_t virtualConnectionId_;

		StreamWindowBuffer sendBuffer_;
		uint16_t sendSlidingWindow_ = 0;
		uint32_t sendCongestionWindow_ = 1;
		std::chrono::steady_clock::time_point sendLastAckReceivedTime_ = std::chrono::steady_clock::now();
		std::vector<std::shared_ptr<SendSegment>> sendSegmentsInFlight_;
		SegmentCallback sendCallback_; //Set if sendBuffer_ is full before appended, Called after sendBuffer_ is not full

		StreamWindowBuffer receiveBuffer_;
		std::deque<ReceiveSegment> receiveSegmentsOk_;
		SegmentCallback receiveCallback_; //Blocks if receiveSegments_ is empty, Called after new data appeared

		asio::io_context &ioContext_;
		LoadBalancingManager &parent_;
		std::recursive_mutex mutex_;
		asio::steady_timer shutdownTimer_;
		uint8_t shutdownFlags_ = 0;
		bool inQueue_ = false, shutdownTimerSet_ = false, closed_ = false;
	};
public:
	LoadBalancingManager(asio::io_context &ioCtx) :ioContext_(ioCtx) {}

	void AsyncConnect(std::function<void(error_code, uint32_t)> &&completeHandler);
	void AsyncAccept(std::function<void(error_code, uint32_t)> &&completeHandler);

	void AsyncSend(uint32_t vConnId, const const_buffer &buffer, prx_tcp_socket::transfer_callback &&completeHandler);
	void AsyncReceive(uint32_t vConnId, const mutable_buffer &buffer, prx_tcp_socket::transfer_callback &&completeHandler);

	void Shutdown(uint32_t vConnId);

	void NewConnection(size_t index, std::unique_ptr<prx_tcp_socket> &&socket, uint16_t rtt);
	virtual void OnConnectionReset(size_t index) {}
protected:
	asio::io_context &IoContext() { return ioContext_; }
private:
	void AppendPendingSendSegment(uint32_t virtualConnectionId);
	void DispatchPendingSendSegment();

	void ReceiveSegment(const std::shared_ptr<BaseConnection> &receiveSocket);
	void EndReceiveSegment(const std::shared_ptr<BaseConnection> &receiveSocket, size_t len);
	void EndReceiveSegmentWithError(const std::shared_ptr<BaseConnection> &receiveSocket);

	void OnVirtualConnectionClosed(uint32_t virtualConnectionId);

	std::shared_ptr<BaseConnection> OccupyConnection();
	void ReleaseConnection(std::shared_ptr<BaseConnection> &&conn, bool failed);

	asio::io_context &ioContext_;

	std::recursive_mutex generalMutex_;
	std::deque<uint32_t> requestQueue_;
	std::unordered_set<uint32_t> requestQueueSet_;
	std::unordered_map<size_t, std::shared_ptr<BaseConnection>> idleConnections_;
	std::unordered_map<uint32_t, std::shared_ptr<VirtualConnection>> virtualConnections_;
	std::deque<uint32_t> acceptQueue_;
	std::function<void(error_code err)> acceptCallback_;
};
