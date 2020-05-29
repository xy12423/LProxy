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

class AcceptorManager
{
public:
	typedef std::function<std::unique_ptr<prx_listener>()> AcceptorFactory;
	typedef std::function<void(error_code, const endpoint &)> AcceptorPreparationCallback;
private:
	struct AcceptorItemIncomplete
	{
		endpoint requestEp;
		std::unique_ptr<prx_listener> acceptor;
		std::list<AcceptorPreparationCallback> callbacks;
	};

	struct AcceptorItem
	{
		std::unique_ptr<prx_listener> acceptor;
		endpoint localEp;
		std::list<AcceptorPreparationCallback> prepCallbacks;
		std::unique_ptr<prx_listener::accept_callback> callback;
	};
public:
	static void AsyncPrepare(const endpoint &endpoint, AcceptorFactory &&factory, AcceptorPreparationCallback &&callback);
	static void AsyncAccept(const endpoint &endpoint, prx_listener::accept_callback &&callback);
	static void CancelAccept(const endpoint &endpoint);

	static void Stop();
private:
	static void AsyncPrepareError(const std::shared_ptr<AcceptorItemIncomplete> &item, error_code err);
	static void CompleteAcceptor(const std::shared_ptr<AcceptorItemIncomplete> &item);
	static void AsyncAcceptStart(const std::shared_ptr<AcceptorItem> &item, prx_listener::accept_callback &&callback);
	static void AsyncAcceptError(const std::shared_ptr<AcceptorItem> &item, error_code err);
	static void AsyncAcceptDo(const std::shared_ptr<AcceptorItem> &item);
	static void AsyncAcceptEnd(const std::shared_ptr<AcceptorItem> &item);
	static void ActivateAcceptor(const std::list<std::pair<endpoint, std::shared_ptr<AcceptorItem>>>::iterator &itr);
	static void RetireAcceptor(const std::shared_ptr<AcceptorItem> &item);
	static void RetireAcceptor(const std::list<std::pair<endpoint, std::shared_ptr<AcceptorItem>>>::iterator &itr);
	static void CleanSpareAcceptors();

	static std::unordered_set<std::shared_ptr<AcceptorItemIncomplete>> incompleteAcceptors_;
	static std::list<std::pair<endpoint, std::shared_ptr<AcceptorItem>>> activeAcceptors_, spareAcceptors_;
	static std::recursive_mutex acceptorsMutex_;
	static std::atomic_bool stopping_;
};

class AcceptorHandle
{
public:
	~AcceptorHandle();

	void AsyncPrepare(const endpoint &endpoint, AcceptorManager::AcceptorFactory &&factory, AcceptorManager::AcceptorPreparationCallback &&callback);
	void AsyncAccept(prx_listener::accept_callback &&callback);
	void CancelAccept();
private:
	std::unique_ptr<endpoint> ep_;
};
