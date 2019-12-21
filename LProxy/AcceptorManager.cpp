#include "pch.h"
#include "AcceptorManager.h"

std::unordered_set<std::shared_ptr<AcceptorManager::AcceptorItemIncomplete>> AcceptorManager::incompleteAcceptors_;
std::list<std::pair<endpoint, std::shared_ptr<AcceptorManager::AcceptorItem>>> AcceptorManager::activeAcceptors_, AcceptorManager::spareAcceptors_;
std::recursive_mutex AcceptorManager::acceptorsMutex_;
std::atomic_bool AcceptorManager::stopping_(false);

static endpoint kEpEmpty, kEpZero((uint32_t)0, 0);

void AcceptorManager::AsyncPrepare(const endpoint &ep, AcceptorFactory &&factory, AcceptorPreparationCallback &&callback)
{
	std::lock_guard<std::recursive_mutex> lock(acceptorsMutex_);
	if (stopping_)
		return;

	//Try to find an existing spare acceptor first

	auto itrSpare = spareAcceptors_.rbegin(), itrSpareEnd = spareAcceptors_.rend();
	for (; itrSpare != itrSpareEnd; ++itrSpare)
		if (ep == itrSpare->first)
			break;
	if (itrSpare != itrSpareEnd)
	{
		std::shared_ptr<AcceptorItem> item = itrSpare->second;
		ActivateAcceptor(--(itrSpare.base()));
		callback(0, item->localEp);
		return;
	}

	//No acceptor spare, see if there's one active

	auto itrActive = activeAcceptors_.rbegin(), itrActiveEnd = activeAcceptors_.rend();
	for (; itrActive != itrActiveEnd; ++itrActive)
		if (ep == itrActive->first)
			break;
	if (itrActive != itrActiveEnd)
	{
		itrActive->second->prepCallbacks.push_back(std::move(callback));
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

	item->acceptor = factory();
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

void AcceptorManager::AsyncAccept(const endpoint &ep, prx_listener::accept_callback &&callback)
{
	std::lock_guard<std::recursive_mutex> lock(acceptorsMutex_);
	if (stopping_)
		return;

	//Try to find the acceptor

	auto itrActive = activeAcceptors_.rbegin(), itrActiveEnd = activeAcceptors_.rend();
	for (; itrActive != itrActiveEnd; ++itrActive)
		if (ep == itrActive->first)
			break;
	if (itrActive != itrActiveEnd && !itrActive->second->callback)
		return AsyncAcceptStart(itrActive->second, std::move(callback));

	callback(ERR_OPERATION_FAILURE, nullptr);
}

void AcceptorManager::CancelAccept(const endpoint &ep)
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

	//Cancel accept

	if (itr->second->callback)
	{
		(*itr->second->callback)(ERR_OPERATION_FAILURE, nullptr);
		itr->second->callback.reset();
	}
	AsyncAcceptEnd(itr->second);
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
		p(err, kEpEmpty);

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

	newItem->prepCallbacks = std::move(item->callbacks);
	newItem->acceptor = std::move(item->acceptor);

	activeAcceptors_.emplace_back(item->requestEp, newItem);
	incompleteAcceptors_.erase(item);

	newItem->prepCallbacks.front()(0, newItem->localEp);
	newItem->prepCallbacks.pop_front();
}

void AcceptorManager::AsyncAcceptStart(const std::shared_ptr<AcceptorItem> &item, prx_listener::accept_callback &&callback)
{
	item->callback = std::make_unique<prx_listener::accept_callback>(std::move(callback));
	AsyncAcceptDo(item);
}

void AcceptorManager::AsyncAcceptError(const std::shared_ptr<AcceptorItem> &item, error_code err)
{
	std::lock_guard<std::recursive_mutex> lock(acceptorsMutex_);

	if (item->callback)
		(*item->callback)(err, nullptr);
	for (const auto &p : item->prepCallbacks)
		p(err, kEpEmpty);

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
	item->acceptor->async_accept([item](error_code err, std::unique_ptr<prx_tcp_socket> socket)
	{
		if (err)
		{
			AsyncAcceptError(item, err);
			return;
		}

		std::lock_guard<std::recursive_mutex> lock(acceptorsMutex_);
		if (!item->callback)
			return;
		(*item->callback)(0, std::move(socket));
		item->callback.reset();
		AsyncAcceptEnd(item);
	});
}

void AcceptorManager::AsyncAcceptEnd(const std::shared_ptr<AcceptorItem> &item)
{
	if (item->prepCallbacks.empty())
	{
		RetireAcceptor(item);
	}
	else
	{
		item->prepCallbacks.front()(0, item->localEp);
		item->prepCallbacks.pop_front();
	}
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

AcceptorHandle::~AcceptorHandle()
{
	if (ep_)
		AcceptorManager::CancelAccept(*ep_);
}

void AcceptorHandle::AsyncPrepare(const endpoint &ep, AcceptorManager::AcceptorFactory &&factory, AcceptorManager::AcceptorPreparationCallback &&callback)
{
	AcceptorManager::AsyncPrepare(ep, std::move(factory),
		[this, ep, callback = std::move(callback)](error_code err, const endpoint &epLocal)
	{
		if (!err)
			ep_ = std::make_unique<endpoint>(ep);
		callback(err, epLocal);
	});
}

void AcceptorHandle::AsyncAccept(prx_listener::accept_callback &&callback)
{
	if (!ep_)
	{
		callback(ERR_OPERATION_FAILURE, nullptr);
		return;
	}
	AcceptorManager::AsyncAccept(*ep_,
		[this, callback = std::move(callback)](error_code err, std::unique_ptr<prx_tcp_socket> &&socket)
	{
		ep_.reset();
		callback(err, std::move(socket));
	});
}

void AcceptorHandle::CancelAccept()
{
	if (!ep_)
		return;
	AcceptorManager::CancelAccept(*ep_);
	ep_.reset();
}
