#ifndef PCH_H
#define PCH_H

#include <cassert>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <climits>
#include <cstdlib>
#include <ctime>

#include <iostream>
#include <fstream>
#include <sstream>

#include <array>
#include <vector>
#include <list>
#include <set>
#include <map>
#include <unordered_set>
#include <unordered_map>
#include <string>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <limits>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

#include <boost/asio.hpp>

#include <libprxsocket/socket_raw.h>
#include <libprxsocket/socket_http.h>
#include <libprxsocket/socket_socks5.h>
#include <libprxsocket/socket_websock.h>

#ifdef _MSC_VER
#pragma comment(lib, "cryptlib.lib")
#pragma comment(lib, "libprxsocket.lib")
#endif

namespace asio = boost::asio;

#endif //PCH_H
