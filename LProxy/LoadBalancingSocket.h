#pragma once

class LoadBalancingManager;

class LoadBalancingSocket final : public prx_tcp_socket
{
public:
	LoadBalancingSocket(LoadBalancingManager &parent) :parent_(parent) {}
	LoadBalancingSocket(LoadBalancingManager &parent, uint32_t virtualConnectionId)
		:parent_(parent), connected_(true), virtualConnectionId_(virtualConnectionId)
	{
	}

	virtual bool is_open() override { return true; }
	virtual bool is_connected() override { return connected_; }

	virtual void local_endpoint(endpoint &ep, error_code &ec) override { ec = ERR_UNSUPPORTED; }
	virtual void remote_endpoint(endpoint &ep, error_code &ec) override { ec = ERR_UNSUPPORTED; }

	virtual void open(error_code &ec) override { ec = 0; }
	virtual void async_open(null_callback &&complete_handler) override { complete_handler(0); }

	virtual void bind(const endpoint &endpoint, error_code &ec) override { ec = ERR_UNSUPPORTED; }
	virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override { complete_handler(ERR_UNSUPPORTED); }

	virtual void connect(const endpoint &endpoint, error_code &ec) override { ec = ERR_UNSUPPORTED; }
	virtual void async_connect(const endpoint &endpoint, null_callback &&complete_handler) override;

	virtual void send(const const_buffer &buffer, size_t &transferred, error_code &ec) override { ec = ERR_UNSUPPORTED; }
	virtual void async_send(const const_buffer &buffer, transfer_callback &&complete_handler) override;
	virtual void recv(const mutable_buffer &buffer, size_t &transferred, error_code &ec) override { ec = ERR_UNSUPPORTED; }
	virtual void async_recv(const mutable_buffer &buffer, transfer_callback &&complete_handler) override;
	virtual void read(mutable_buffer_sequence &&buffer, error_code &ec) override { ec = ERR_UNSUPPORTED; }
	virtual void async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler) override;
	virtual void write(const_buffer_sequence &&buffer, error_code &ec) override { ec = ERR_UNSUPPORTED; }
	virtual void async_write(const_buffer_sequence &&buffer, null_callback &&complete_handler) override;

	virtual void close(error_code &ec) override;
	virtual void async_close(null_callback &&complete_handler);
private:
	virtual void async_read(const std::shared_ptr<mutable_buffer_sequence> &buffers, const std::shared_ptr<null_callback> &callback);

	LoadBalancingManager &parent_;
	bool connected_ = false;
	uint32_t virtualConnectionId_ = -1;
};

class LoadBalancingListener final : public prx_listener
{
public:
	LoadBalancingListener(LoadBalancingManager &parent) :parent_(parent) {}

	virtual bool is_open() override { return true; }
	virtual bool is_listening() override { return true; }

	virtual void local_endpoint(endpoint &ep, error_code &ec) override { ec = ERR_UNSUPPORTED; }

	virtual void open(error_code &ec) override { ec = 0; }
	virtual void async_open(null_callback &&complete_handler) override { complete_handler(0); }

	virtual void bind(const endpoint &endpoint, error_code &ec) override { ec = ERR_UNSUPPORTED; }
	virtual void async_bind(const endpoint &endpoint, null_callback &&complete_handler) override { complete_handler(ERR_UNSUPPORTED); }

	virtual void listen(error_code &ec) override { ec = 0; }
	virtual void async_listen(null_callback &&complete_handler) override { complete_handler(0); }

	virtual void accept(std::unique_ptr<prx_tcp_socket> &socket, error_code &err) override;
	virtual void async_accept(accept_callback &&complete_handler) override;

	virtual void close(error_code &ec) override { ec = 0; }
	virtual void async_close(null_callback &&complete_handler) override { complete_handler(0); }
private:
	LoadBalancingManager &parent_;
};
