#pragma once

class AcceptorManager
{
public:
	typedef std::function<prx_listener_base*()> accFactory;
	typedef std::function<void(error_code, const endpoint &)> accPrepCallback;
private:
	struct AcceptorItemIncomplete
	{
		endpoint requestEp;
		std::unique_ptr<prx_listener_base> acceptor;
		std::list<accPrepCallback> callbacks;
	};

	struct AcceptorItem
	{
		std::unique_ptr<prx_listener_base> acceptor;
		endpoint localEp;
		std::list<std::pair<size_t, prx_listener_base::accept_callback>> callbacks;
		size_t nextId = 0;
	};
public:
	static void AsyncPrepare(const endpoint &endpoint, accFactory &&factory, accPrepCallback &&callback);
	static size_t AsyncAccept(const endpoint &endpoint, prx_listener_base::accept_callback &&callback);
	static void CancelAccept(const endpoint &endpoint, size_t id);

	static void Stop();
private:
	static void AsyncPrepareError(const std::shared_ptr<AcceptorItemIncomplete> &item, error_code err);
	static void CompleteAcceptor(const std::shared_ptr<AcceptorItemIncomplete> &item);
	static size_t AsyncAcceptStart(const std::shared_ptr<AcceptorItem> &item, prx_listener_base::accept_callback &&callback);
	static void AsyncAcceptError(const std::shared_ptr<AcceptorItem> &item, error_code err);
	static void AsyncAcceptDo(const std::shared_ptr<AcceptorItem> &item);
	static void ActivateAcceptor(const std::list<std::pair<endpoint, std::shared_ptr<AcceptorItem>>>::iterator &itr);
	static void RetireAcceptor(const std::shared_ptr<AcceptorItem> &item);
	static void RetireAcceptor(const std::list<std::pair<endpoint, std::shared_ptr<AcceptorItem>>>::iterator &itr);
	static void CleanSpareAcceptors();

	static std::unordered_set<std::shared_ptr<AcceptorItemIncomplete>> incompleteAcceptors_;
	static std::list<std::pair<endpoint, std::shared_ptr<AcceptorItem>>> activeAcceptors_, spareAcceptors_;
	static std::recursive_mutex acceptorsMutex_;
	static std::atomic_bool stopping_;
};
