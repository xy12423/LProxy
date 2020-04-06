CXX = g++
CXXFLAGS = -c -pthread -I ~/boost -I ~/libprxsocket -std=c++14
LFLAGS = -pthread -L ~/boost/stage/lib -L ~/libprxsocket/libprxsocket -lprxsocket -lboost_system -lcryptopp -static-libstdc++

ifeq ($(RELEASE), 1)
	CXXFLAGS += -g3 -O2 -DNDEBUG
else
	CXXFLAGS += -g3 -O0 -D_DEBUG
endif

objects = AcceptorManager.o LoadBalancingManager.o LoadBalancingSocket.o ProxySession.o Socks4Session.o Socks5Session.o ProxyServer.o main.o

all : lproxy

lproxy : $(objects)
	$(CXX) $(objects) $(LFLAGS) -o lproxy
AcceptorManager.o : pch.h AcceptorManager.h AcceptorManager.cpp
	$(CXX) AcceptorManager.cpp $(CXXFLAGS) -o AcceptorManager.o
LoadBalancingManager.o : pch.h LoadBalancingManager.h LoadBalancingManager.cpp
	$(CXX) LoadBalancingManager.cpp $(CXXFLAGS) -o LoadBalancingManager.o
LoadBalancingSocket.o : pch.h LoadBalancingManager.h LoadBalancingSocket.h LoadBalancingSocket.cpp
	$(CXX) LoadBalancingSocket.cpp $(CXXFLAGS) -o LoadBalancingSocket.o
ProxySession.o : pch.h ProxySession.h ProxyServer.h ProxySession.cpp
	$(CXX) ProxySession.cpp $(CXXFLAGS) -o ProxySession.o
Socks4Session.o : pch.h ProxySession.h AcceptorManager.h Socks4Session.h ProxyServer.h Socks4Session.cpp
	$(CXX) Socks4Session.cpp $(CXXFLAGS) -o Socks4Session.o
Socks5Session.o : pch.h ProxySession.h AcceptorManager.h Socks5Session.h ProxyServer.h Socks5Session.cpp
	$(CXX) Socks5Session.cpp $(CXXFLAGS) -o Socks5Session.o
ProxyServer.o : pch.h ProxyServer.h Socks4Session.h Socks5Session.h AcceptorManager.h ProxyServer.cpp
	$(CXX) ProxyServer.cpp $(CXXFLAGS) -o ProxyServer.o
main.o : pch.h ProxyServer.h AcceptorManager.h LoadBalancingManager.h LoadBalancingSocket.h main.cpp
	$(CXX) main.cpp $(CXXFLAGS) -o main.o

clean :
	rm -rf *.o lproxy
