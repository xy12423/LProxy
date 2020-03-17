#pragma once

class LoadBalancingManager
{
	static constexpr auto kTimeRetry = std::chrono::milliseconds(100);
	enum
	{
		SYN = 0x01,
		EST = 0x02,
		FIN = 0x04,
		RST = 0x08,
	};

	struct BaseConnection
	{
		BaseConnection() = default;
		BaseConnection(size_t idx, std::shared_ptr<prx_tcp_socket> &&conn) :index(idx), connection(std::move(conn)) {}
		BaseConnection(const BaseConnection &) = delete;
		BaseConnection(BaseConnection &&) = default;

		size_t index = -1;
		const std::shared_ptr<prx_tcp_socket> connection;
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
		~Connection() { if (connection.connection) parent.ReleaseConnection(std::move(connection), connectionFailed); }

		prx_tcp_socket *AccessConnection() { return connection.connection.get(); }
		void SetConnectionFailed() { connectionFailed = true; }
		void ReleaseConnection() { parent.ReleaseConnection(std::move(connection), connectionFailed); }
	private:
		LoadBalancingManager &parent;
		BaseConnection connection;
		bool connectionFailed = false;
	};

	class VirtualConnection : std::enable_shared_from_this<VirtualConnection>
	{
		using SendRequestCallback = null_callback;

		struct SendRequest
		{
			SendRequest(asio::io_context &ioCtx, bool isAcknowledgement = false) :retryTimer(ioCtx), isPureAck(isAcknowledgement) {}

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
			const bool isPureAck;
		};
	public:
		VirtualConnection(uint32_t vConnId, asio::io_context &ioCtx, LoadBalancingManager &parent_)
			:virtualConnectionId_(vConnId), ioContext_(ioCtx), parent_(parent_)
		{
		}
		~VirtualConnection() { if (sendCallback_) sendCallback_(ERR_OPERATION_FAILURE); }

		uint32_t VirtualConnectionId() const { return virtualConnectionId_; }

		void AppendSendRequest(uint8_t flags, const char *payload, uint16_t payloadSize, SendRequestCallback &&completeHandler);
		void DoSendRequest(const std::shared_ptr<Connection> &connection);
	private:
		void BeginSendRequest();
		void RetrySendRequest(const std::shared_ptr<SendRequest> &sendingSegment, size_t tryCount);

		const uint32_t virtualConnectionId_;

		std::vector<std::shared_ptr<SendRequest>> sendSegments_;
		uint32_t sendSegmentIdNext_ = 0;
		size_t sendWindow_ = 0;
		SendRequestCallback sendCallback_; //Set if sendSegments_ is full before appended, Called after sendSegments_ is not full

		std::pair<uint32_t, std::vector<char>> receiveSegments_[8];
		uint32_t receiveSegmentIdComplete_ = -1, receiveSegmentCount_ = 0;
		size_t receiveSegmentOffset = 0;
		//receiveCallback; //Blocks if receiveSegments_ is empty, Called after data is copied to dst

		asio::io_context &ioContext_;
		LoadBalancingManager &parent_;
		std::recursive_mutex mutex_;
		bool inQueue_ = false, closed = false;
	};
public:
	void AppendPendingSendRequest(uint32_t virtualConnectionId);
	void DispatchPendingSendRequest();
private:
	void BeginReceiveSegment(const std::shared_ptr<prx_tcp_socket> &receiveSocket);

	BaseConnection OccupyConnection();
	void ReleaseConnection(BaseConnection &&conn, bool failed);
	void InitConnection(size_t index);

	virtual size_t NewBaseTcpSocketMaxIndex() const = 0;
	virtual void NewBaseTcpSocket(size_t index, prx_listener::accept_callback &&completeHandler) const = 0;

	asio::io_context &ioContext_;

	std::recursive_mutex generalMutex_;
	std::deque<uint32_t> requestQueue_;
	std::unordered_set<uint32_t> requestQueueSet_;
	std::unordered_map<uint32_t, BaseConnection> idleConnections_;
	std::unordered_map<uint32_t, std::shared_ptr<VirtualConnection>> virtualConnections_;
};
