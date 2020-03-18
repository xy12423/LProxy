#pragma once

class LoadBalancingManager
{
	static constexpr uint16_t kTimeRetryMin = 100;
	enum
	{
		SYN = 0x01,
		FIN = 0x02,
		RST = 0x04,
		ACK = 0x08,
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

		char receiveBuffer[0x10010];
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

	class VirtualConnection : std::enable_shared_from_this<VirtualConnection>
	{
		using SegmentCallback = null_callback;

		static constexpr uint16_t kMaxWindowSize = 8;

		enum
		{
			SHUTDOWN_SEND     = 0x01,
			SHUTDOWN_RECEIVE  = 0x02,
			SHUTDOWN_BOTH     = SHUTDOWN_SEND | SHUTDOWN_RECEIVE,
			SHUTDOWN_SENT     = 0x04,
			SHUTDOWN_COMPLETE = SHUTDOWN_BOTH | SHUTDOWN_SENT,
		};

		struct SendSegment
		{
			SendSegment(asio::io_context &ioCtx, uint32_t segId, bool isAck) :retryTimer(ioCtx), segmentId(segId), isAcknowledgement(isAck) {}

			enum
			{
				READY,
				SENT,
				ACKNOWLEDGED,
			};

			std::vector<char> data; //Contains complete segment including header with ACK left empty(will be filled when sending)
			boost::asio::steady_timer retryTimer;
			size_t tryCount = 0;
			uint8_t state = READY;

			const uint32_t segmentId;
			const bool isAcknowledgement;
		};
	public:
		VirtualConnection(uint32_t vConnId, asio::io_context &ioCtx, LoadBalancingManager &parent_)
			:virtualConnectionId_(vConnId), ioContext_(ioCtx), parent_(parent_), shutdownTimer_(ioCtx)
		{
		}
		~VirtualConnection() { if (sendCallback_) sendCallback_(ERR_OPERATION_FAILURE); if (receiveCallback_) receiveCallback_(ERR_OPERATION_FAILURE); }

		uint32_t VirtualConnectionId() const { return virtualConnectionId_; }

		void AppendSendSegment(uint8_t flags, const char *payload, uint16_t payloadSize, SegmentCallback &&completeHandler);
		void DoSendSegment(const std::shared_ptr<Connection> &connection);

		void OnReceiveSegment(const char *data, size_t size);

		void Shutdown();
		void Reset();
	private:
		void BeginSendSegment();
		void RetrySendSegment(const std::shared_ptr<SendSegment> &sendingSegment, size_t tryCount);

		void ShutdownCheck();

		const uint32_t virtualConnectionId_;

		std::vector<std::shared_ptr<SendSegment>> sendSegments_;
		uint32_t sendSegmentIdNext_ = 0, sendLaskAck_ = -1;
		uint8_t sendWindow_ = 1;
		SegmentCallback sendCallback_; //Set if sendSegments_ is full before appended, Called after sendSegments_ is not full
		uint32_t sendSegmentIdPending_ = -1;

		std::pair<bool, std::vector<char>> receiveSegments_[kMaxWindowSize];
		uint32_t receiveSegmentIdComplete_ = -1, receiveSegmentCount_ = 0;
		uint32_t receiveSegmentOffset_ = 0;
		SegmentCallback receiveCallback_; //Blocks if receiveSegments_ is empty, Called after data is copied to dst

		asio::io_context &ioContext_;
		LoadBalancingManager &parent_;
		std::recursive_mutex mutex_;
		asio::steady_timer shutdownTimer_;
		uint8_t shutdownFlags = 0;
		bool inQueue_ = false, closed = false;
	};
public:
private:
	void AppendPendingSendSegment(uint32_t virtualConnectionId);
	void DispatchPendingSendSegment();

	void ReceiveSegment(const std::shared_ptr<BaseConnection> &receiveSocket);
	void EndReceiveSegment(const std::shared_ptr<BaseConnection> &receiveSocket, size_t len);
	void EndReceiveSegmentWithError(const std::shared_ptr<BaseConnection> &receiveSocket);

	void OnVirtualConnectionClosed(uint32_t virtualConnectionId);

	std::shared_ptr<BaseConnection> OccupyConnection();
	void ReleaseConnection(std::shared_ptr<BaseConnection> &&conn, bool failed);
	void InitConnection(size_t index);

	virtual size_t NewBaseTcpSocketMaxIndex() const = 0;
	virtual void NewBaseTcpSocket(size_t index, std::function<void(std::unique_ptr<prx_tcp_socket> &&, uint16_t)> &&completeHandler) const = 0;

	asio::io_context &ioContext_;

	std::recursive_mutex generalMutex_;
	std::deque<uint32_t> requestQueue_;
	std::unordered_set<uint32_t> requestQueueSet_;
	std::unordered_map<uint32_t, std::shared_ptr<BaseConnection>> idleConnections_;
	std::unordered_map<uint32_t, std::shared_ptr<VirtualConnection>> virtualConnections_;
};
