CXX = g++
CXXFLAGS = -c -pthread -I ~/libprxsocket -std=c++17 -DBOOST_BIND_GLOBAL_PLACEHOLDERS -fsanitize=address
LFLAGS = -pthread -L ~/libprxsocket/libprxsocket -fsanitize=address -lprxsocket -lboost_system -lcrypto -lssl

ifeq ($(RELEASE), 1)
	CXXFLAGS += -g3 -O2 -DNDEBUG
else
	CXXFLAGS += -g3 -O0 -D_DEBUG
endif

objects = AcceptorManager.o ProxySession.o Socks4Session.o Socks5Session.o ProxyServer.o ServerConfiguration.o ServerConfigurationNodes.o ServerConfigurationVisitor.o main.o

all : lproxy

lproxy : $(objects)
	$(CXX) $(objects) $(LFLAGS) -o lproxy
AcceptorManager.o : pch.h AcceptorManager.h AcceptorManager.cpp
	$(CXX) AcceptorManager.cpp $(CXXFLAGS) -o AcceptorManager.o
ProxySession.o : pch.h ProxySession.h ProxyServer.h ProxySession.cpp
	$(CXX) ProxySession.cpp $(CXXFLAGS) -o ProxySession.o
Socks4Session.o : pch.h ProxySession.h AcceptorManager.h Socks4Session.h ProxyServer.h Socks4Session.cpp
	$(CXX) Socks4Session.cpp $(CXXFLAGS) -o Socks4Session.o
Socks5Session.o : pch.h ProxySession.h AcceptorManager.h Socks5Session.h ProxyServer.h Socks5Session.cpp
	$(CXX) Socks5Session.cpp $(CXXFLAGS) -o Socks5Session.o
ProxyServer.o : pch.h ProxyServer.h Socks4Session.h Socks5Session.h AcceptorManager.h ProxyServer.cpp
	$(CXX) ProxyServer.cpp $(CXXFLAGS) -o ProxyServer.o
ServerConfiguration.o : pch.h ServerConfiguration.h ServerConfigurationNode.h ServerConfigurationNodes.h ServerConfigurationVisitor.h ServerConfiguration.cpp
	$(CXX) ServerConfiguration.cpp ${CXXFLAGS} -o ServerConfiguration.o
ServerConfigurationNodes.o : pch.h ServerConfigurationNode.h ServerConfigurationNodes.h ServerConfigurationVisitor.h ServerConfigurationNodes.cpp
	$(CXX) ServerConfigurationNodes.cpp ${CXXFLAGS} -o ServerConfigurationNodes.o
ServerConfigurationVisitor.o : pch.h ServerConfigurationNode.h ServerConfigurationNodes.h ServerConfigurationVisitor.h ServerConfigurationVisitor.cpp
	$(CXX) ServerConfigurationVisitor.cpp ${CXXFLAGS} -o ServerConfigurationVisitor.o
main.o : pch.h ProxyServer.h AcceptorManager.h ServerConfiguration.h main.cpp
	$(CXX) main.cpp $(CXXFLAGS) -o main.o

clean :
	rm -rf *.o lproxy
