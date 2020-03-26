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
		using SegmentCallback = null_callback;

		static constexpr uint16_t kTimeRetryMin = 100;
		static constexpr auto kTimeShutdownWait = std::chrono::seconds(10);
		static constexpr uint16_t kMaxWindowSize = 8;
		static constexpr size_t kMaxSegmentSize = 4096;

		static constexpr uint16_t timeOut(uint16_t rtt, size_t tryCount)
		{
			return std::min(kTimeRetryMin, rtt) * (tryCount <= 4 ? tryCount : (1 << (tryCount - 2)));
		}

		enum
		{
			SHUTDOWN_SEND     = 0x01,
			SHUTDOWN_RECEIVE  = 0x02,
			SHUTDOWN_BOTH     = SHUTDOWN_SEND | SHUTDOWN_RECEIVE,
			SHUTDOWN_SENT     = 0x04,
			SHUTDOWN_COMPLETE = SHUTDOWN_BOTH | SHUTDOWN_SENT,
			SHUTDOWN_FORCE    = 0x08,
			SHUTDOWN_RESET    = SHUTDOWN_COMPLETE | SHUTDOWN_FORCE,
		};

		struct SendSegment
		{
			SendSegment(asio::io_context &ioCtx, uint32_t segId, bool isAck) :segmentId(segId), isAcknowledgement(isAck), retryTimer(ioCtx) {}

			enum
			{
				READY,
				SENT,
				ACKNOWLEDGED,
			};

			const uint32_t segmentId;
			const bool isAcknowledgement;

			uint16_t state = READY;
			boost::asio::steady_timer retryTimer;
			size_t tryCount = 0;

			std::chrono::steady_clock::time_point timeStart, timeTry;

			std::vector<char> data; //Contains complete segment including header with ACK left empty(will be filled when sending)
		};

		struct ReceiveSegment
		{
			bool ok = false;
			uint16_t flags = 0;

			std::vector<char> data;
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
		void AppendSendSegment(uint16_t flags, const char *payload, uint16_t payloadSize, SegmentCallback &&completeHandler);
		void AppendSendSegment(uint16_t flags, const_buffer_sequence &&payload, SegmentCallback &&completeHandler);
		//DO NOT DIRECTLY CALL THIS
		void AppendSendSegment(uint16_t flags, std::vector<char> &&segmentWithPartOfHeader, SegmentCallback &&completeHandler);
		void BeginSendSegment();
		void BeginSendSegmentAck();
		void RetrySendSegment(const std::shared_ptr<SendSegment> &sendingSegment, size_t tryCount);

		//Returns whether receive window is changed
		bool ConsumeReceiveSegment(char *dst, size_t dstSize, size_t &transferred);
		bool ConsumeReceiveSegmentEmpty();

		void ShutdownCheck();

		const uint32_t virtualConnectionId_;

		std::vector<std::shared_ptr<SendSegment>> sendSegments_;
		uint32_t sendSegmentIdNext_ = 0, sendLaskAck_ = -1;
		uint16_t sendWindow_ = 1;
		SegmentCallback sendCallback_; //Set if sendSegments_ is full before appended, Called after sendSegments_ is not full
		uint32_t sendSegmentIdPending_ = -1;

		ReceiveSegment receiveSegments_[kMaxWindowSize];
		uint32_t receiveSegmentIdOffset_ = 0, receiveSegmentComplete_ = -1, receiveSegmentCount_ = 0;
		size_t receiveSegmentDataOffset_ = 0;
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
