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

class ProxyServer;

class ProxySession : public std::enable_shared_from_this<ProxySession>
{
public:
	ProxySession(ProxyServer &server);
	ProxySession(const ProxySession &) = delete;
	ProxySession(ProxySession &&) = delete;
	virtual ~ProxySession();

	virtual void Start() = 0;
	virtual void Start(buffer_with_data_store &&leftover) = 0;
	virtual void Stop() = 0;

	const endpoint &UpstreamEndpoint() const { return upEp_; }
	const endpoint &DownstreamEndpoint() const { return downEp_; }
	const std::string &SessionType() const { return type_; }

	size_t TotalBytesUp() const { return totalUp_; }
	size_t TotalBytesDown() const { return totalDown_; }
	size_t LastBytesUp() const { return lastUp_; }
	size_t LastBytesDown() const { return lastDown_; }
	void ResetLastBytes() { lastUp_ = lastDown_ = 0; }
protected:
	endpoint &AccessUpstreamEndpoint() { return upEp_; }
	endpoint &AccessDownstreamEndpoint() { return downEp_; }
	std::string &AccessSessionType() { return type_; }

	void AddBytesUp(size_t diff) { totalUp_ += diff; lastUp_ += diff; }
	void AddBytesDown(size_t diff) { totalDown_ += diff; lastDown_ += diff; }

	ProxyServer &server_;
private:
	endpoint upEp_, downEp_;
	std::string type_;
	std::atomic_size_t totalUp_{ 0 }, totalDown_{ 0 }, lastUp_{ 0 }, lastDown_{ 0 };
};
