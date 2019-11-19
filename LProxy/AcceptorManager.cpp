#include "pch.h"
#include "AcceptorManager.h"

std::unordered_set<std::shared_ptr<AcceptorManager::AcceptorItemIncomplete>> AcceptorManager::incompleteAcceptors_;
std::list<std::pair<endpoint, std::shared_ptr<AcceptorManager::AcceptorItem>>> AcceptorManager::activeAcceptors_, AcceptorManager::spareAcceptors_;
std::recursive_mutex AcceptorManager::acceptorsMutex_;
std::atomic_bool AcceptorManager::stopping_ = false;

static endpoint emptyEndpoint;

void AcceptorManager::AsyncPrepare(const endpoint &ep, accFactory &&factory, accPrepCallback &&callback)
{
	std::lock_guard<std::recursive_mutex> lock(acceptorsMutex_);
	if (stopping_)
		return;

	//Try to find an existing acceptor first

	auto itr = activeAcceptors_.rbegin(), itrEnd = activeAcceptors_.rend();
	for (; itr != itrEnd; ++itr)
		if (ep == itr->first)
			break;
	if (itr != itrEnd)
	{
		callback(0, itr->second->localEp);
		return;
	}

	itr = spareAcceptors_.rbegin(), itrEnd = spareAcceptors_.rend();
	for (; itr != itrEnd; ++itr)
		if (ep == itr->first)
			break;
	if (itr != itrEnd)
	{
		callback(0, itr->second->localEp);
		return;
	}

	//No acceptor ready, see if there's one preparing

	auto itrInc = incompleteAcceptors_.begin(), itrIncEnd = incompleteAcceptors_.end();
	for (; itrInc != itrIncEnd; ++itrInc)
		if (ep == (*itrInc)->requestEp)
			break;
	if (itrInc != itrIncEnd)
	{
		(*itrInc)->callbacks.push_back(std::move(callback));
		return;
	}

	//Can't find one, make a new acceptor

	std::shared_ptr<AcceptorItemIncomplete> item = std::make_shared<AcceptorItemIncomplete>();
	item->requestEp = ep;
	item->callbacks.push_back(std::move(callback));
	incompleteAcceptors_.insert(item);

	item->acceptor.reset(factory());
	item->acceptor->async_open([item, ep](error_code err) {
		if (err)
		{
			AsyncPrepareError(item, err);
			return;
		}
		item->acceptor->async_bind(ep,
			[item, ep](error_code err)
		{
			if (err)
			{
				AsyncPrepareError(item, err);
				return;
			}
			item->acceptor->async_listen([item, ep](error_code err)
			{
				if (err)
				{
					AsyncPrepareError(item, err);
					return;
				}

				std::lock_guard<std::recursive_mutex> lock(acceptorsMutex_);
				CompleteAcceptor(item);
			});
		});
	});
}

size_t AcceptorManager::AsyncAccept(const endpoint &ep, prx_listener_base::accept_callback &&callback)
{
	std::lock_guard<std::recursive_mutex> lock(acceptorsMutex_);
	if (stopping_)
		return 0;

	//Try to find the acceptor

	auto itr = activeAcceptors_.rbegin(), itrEnd = activeAcceptors_.rend();
	for (; itr != itrEnd; ++itr)
		if (ep == itr->first)
			break;
	if (itr != itrEnd)
	{
		return AsyncAcceptStart(itr->second, std::move(callback));
	}

	itr = spareAcceptors_.rbegin(), itrEnd = spareAcceptors_.rend();
	for (; itr != itrEnd; ++itr)
		if (ep == itr->first)
			break;
	if (itr != itrEnd)
	{
		auto item = itr->second;
		ActivateAcceptor(--(itr.base()));
		return AsyncAcceptStart(item, std::move(callback));
	}

	callback(ERR_OPERATION_FAILURE, nullptr);
	return 0;
}

void AcceptorManager::CancelAccept(const endpoint &ep, size_t id)
{
	std::lock_guard<std::recursive_mutex> lock(acceptorsMutex_);
	if (stopping_)
		return;

	//Try to find the acceptor

	auto itr = activeAcceptors_.begin(), itrEnd = activeAcceptors_.end();
	for (; itr != itrEnd; ++itr)
		if (ep == itr->first)
			break;
	if (itr == itrEnd)
		return;

	//Try to find the callback

	auto &callbacks = itr->second->callbacks;
	auto itrCallback = callbacks.begin(), itrCallbackEnd = callbacks.end();
	for (; itrCallback != itrCallbackEnd; ++itrCallback)
	{
		if (itrCallback->first == id)
		{
			itrCallback->second(ERR_OPERATION_FAILURE, nullptr);
			callbacks.erase(itrCallback);
			if (callbacks.empty())
				RetireAcceptor(itr);
			return;
		}
	}
}

void AcceptorManager::Stop()
{
	if (stopping_.exchange(true))
		return;
	std::lock_guard<std::recursive_mutex> lock(acceptorsMutex_);
	error_code err;

	auto itr = activeAcceptors_.begin(), itrEnd = activeAcceptors_.end();
	for (; itr != itrEnd; ++itr)
		itr->second->acceptor->close(err);

	itr = spareAcceptors_.begin(), itrEnd = spareAcceptors_.end();
	for (; itr != itrEnd; ++itr)
		itr->second->acceptor->close(err);
}

void AcceptorManager::AsyncPrepareError(const std::shared_ptr<AcceptorItemIncomplete> &item, error_code err)
{
	std::lock_guard<std::recursive_mutex> lock(acceptorsMutex_);

	for (const auto &p : item->callbacks)
		p(err, emptyEndpoint);

	item->acceptor->close(err);
	incompleteAcceptors_.erase(item);
}

void AcceptorManager::CompleteAcceptor(const std::shared_ptr<AcceptorItemIncomplete> &item)
{
	std::shared_ptr<AcceptorItem> newItem = std::make_shared<AcceptorItem>();

	error_code err;
	item->acceptor->local_endpoint(newItem->localEp, err);
	if (err)
	{
		AsyncPrepareError(item, err);
		return;
	}
	newItem->acceptor = std::move(item->acceptor);

	spareAcceptors_.emplace_back(item->requestEp, newItem);
	incompleteAcceptors_.erase(item);
	CleanSpareAcceptors();

	for (const auto &callback : item->callbacks)
		callback(0, newItem->localEp);
}

size_t AcceptorManager::AsyncAcceptStart(const std::shared_ptr<AcceptorItem> &item, prx_listener_base::accept_callback &&callback)
{
	bool stopped = item->callbacks.empty();
	size_t nextId = item->nextId++;
	item->callbacks.emplace_back(nextId, std::move(callback));
	if (stopped)
		AsyncAcceptDo(item);
	return nextId;
}

void AcceptorManager::AsyncAcceptError(const std::shared_ptr<AcceptorItem> &item, error_code err)
{
	std::lock_guard<std::recursive_mutex> lock(acceptorsMutex_);

	for (const auto &p : item->callbacks)
		p.second(err, nullptr);

	auto itr = activeAcceptors_.begin(), itrEnd = activeAcceptors_.end();
	for (; itr != itrEnd; ++itr)
		if (item == itr->second)
			break;
	if (itr != itrEnd)
	{
		activeAcceptors_.erase(itr);
		return;
	}

	itr = spareAcceptors_.begin(), itrEnd = spareAcceptors_.end();
	for (; itr != itrEnd; ++itr)
		if (item == itr->second)
			break;
	if (itr != itrEnd)
	{
		spareAcceptors_.erase(itr);
		return;
	}
}

void AcceptorManager::AsyncAcceptDo(const std::shared_ptr<AcceptorItem> &item)
{
	item->acceptor->async_accept([item](error_code err, prx_tcp_socket_base *socketPtr)
	{
		std::unique_ptr<prx_tcp_socket_base> socket(socketPtr);
		if (err)
		{
			AsyncAcceptError(item, err);
			return;
		}

		std::lock_guard<std::recursive_mutex> lock(acceptorsMutex_);
		if (item->callbacks.empty())
			return;
		item->callbacks.front().second(0, socket.release());
		item->callbacks.pop_front();
		if (item->callbacks.empty())
			RetireAcceptor(item);
		else
			AsyncAcceptDo(item);
	});
}

void AcceptorManager::ActivateAcceptor(const std::list<std::pair<endpoint, std::shared_ptr<AcceptorItem>>>::iterator &itr)
{
	activeAcceptors_.push_back(*itr);
	spareAcceptors_.erase(itr);
}

void AcceptorManager::RetireAcceptor(const std::shared_ptr<AcceptorItem> &item)
{
	//Try to find the acceptor

	auto itr = activeAcceptors_.begin(), itrEnd = activeAcceptors_.end();
	for (; itr != itrEnd; ++itr)
		if (item == itr->second)
			break;
	if (itr != itrEnd)
		RetireAcceptor(itr);
}

void AcceptorManager::RetireAcceptor(const std::list<std::pair<endpoint, std::shared_ptr<AcceptorItem>>>::iterator &itr)
{
	spareAcceptors_.push_back(*itr);
	activeAcceptors_.erase(itr);
	CleanSpareAcceptors();
}

void AcceptorManager::CleanSpareAcceptors()
{
	while (spareAcceptors_.size() > 16)
	{
		error_code err;
		spareAcceptors_.front().second->acceptor->close(err);
		spareAcceptors_.pop_front();
	}
}
