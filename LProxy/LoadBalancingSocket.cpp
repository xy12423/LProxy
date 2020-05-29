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

#include "pch.h"
#include "LoadBalancingSocket.h"
#include "LoadBalancingManager.h"

void LoadBalancingSocket::async_connect(const endpoint &, null_callback &&complete_handler)
{
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	parent_.AsyncConnect([this, callback](error_code err, uint32_t vConnId)
	{
		if (err)
		{
			(*callback)(err);
			return;
		}
		connected_ = true;
		virtualConnectionId_ = vConnId;
		(*callback)(0);
	});
}

void LoadBalancingSocket::async_send(const const_buffer &buffer, transfer_callback &&complete_handler)
{
	if (!connected_)
	{
		complete_handler(ERR_OPERATION_FAILURE, 0);
		return;
	}
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
	parent_.AsyncSend(virtualConnectionId_, buffer,
		[this, callback](error_code err, size_t transferred)
	{
		if (err)
		{
			async_close([this, callback, err](error_code) { (*callback)(err, 0); });
			return;
		}
		(*callback)(0, transferred);
	});
}

void LoadBalancingSocket::async_recv(const mutable_buffer &buffer, transfer_callback &&complete_handler)
{
	if (!connected_)
	{
		complete_handler(ERR_OPERATION_FAILURE, 0);
		return;
	}
	std::shared_ptr<transfer_callback> callback = std::make_shared<transfer_callback>(std::move(complete_handler));
	parent_.AsyncReceive(virtualConnectionId_, buffer,
		[this, callback](error_code err, size_t transferred)
	{
		if (err)
		{
			async_close([this, callback, err](error_code) { (*callback)(err, 0); });
			return;
		}
		(*callback)(0, transferred);
	});
}

void LoadBalancingSocket::async_read(mutable_buffer_sequence &&buffer, null_callback &&complete_handler)
{
	if (buffer.empty())
	{
		complete_handler(0);
		return;
	}
	std::shared_ptr<mutable_buffer_sequence> buffers = std::make_shared<mutable_buffer_sequence>(std::move(buffer));
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	parent_.AsyncReceive(virtualConnectionId_, buffers->front(),
		[this, buffers, callback](error_code err, size_t transferred)
	{
		if (err)
		{
			async_close([this, callback, err](error_code) { (*callback)(err); });
			return;
		}
		buffers->pop_front();
		async_read(buffers, callback);
	});
}

void LoadBalancingSocket::async_read(const std::shared_ptr<mutable_buffer_sequence> &buffers, const std::shared_ptr<null_callback> &callback)
{
	if (buffers->empty())
	{
		(*callback)(0);
		return;
	}
	parent_.AsyncReceive(virtualConnectionId_, buffers->front(),
		[this, buffers, callback](error_code err, size_t transferred)
	{
		if (err)
		{
			async_close([this, callback, err](error_code) { (*callback)(err); });
			return;
		}
		buffers->pop_front();
		async_read(buffers, callback);
	});
}

void LoadBalancingSocket::async_write(const_buffer_sequence &&buffer, null_callback &&complete_handler)
{
	std::shared_ptr<std::vector<char>> data = std::make_shared<std::vector<char>>();
	data->resize(buffer.size_total());
	buffer.gather(data->data(), data->size());
	std::shared_ptr<null_callback> callback = std::make_shared<null_callback>(std::move(complete_handler));
	prx_tcp_socket::async_write(const_buffer(*data),
		[this, data, callback](error_code err)
	{
		if (err)
		{
			async_close([this, callback, err](error_code) { (*callback)(err); });
			return;
		}
		(*callback)(0);
	});
}

void LoadBalancingSocket::close(error_code &ec)
{
	ec = 0;
	connected_ = false;
	parent_.Shutdown(virtualConnectionId_);
	virtualConnectionId_ = -1;
}

void LoadBalancingSocket::async_close(null_callback &&complete_handler)
{
	connected_ = false;
	parent_.Shutdown(virtualConnectionId_);
	virtualConnectionId_ = -1;
	complete_handler(0);
}

void LoadBalancingListener::async_accept(accept_callback &&complete_handler)
{
	std::shared_ptr<accept_callback> callback = std::make_shared<accept_callback>(std::move(complete_handler));
	parent_.AsyncAccept([this, callback](error_code err, uint32_t vConnId)
	{
		if (err)
		{
			(*callback)(err, nullptr);
			return;
		}
		(*callback)(0, std::make_unique<LoadBalancingSocket>(parent_, vConnId));
	});
}
