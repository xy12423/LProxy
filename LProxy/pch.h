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
#include <deque>
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
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace asio = boost::asio;
namespace ptree = boost::property_tree;

#include <cryptopp/md5.h>

#include <libprxsocket/socket_raw.h>
#include <libprxsocket/socket_http.h>
#include <libprxsocket/socket_socks5.h>
#include <libprxsocket/socket_obfs_websock.h>
#include <libprxsocket/socket_ss.h>
#include <libprxsocket/socket_ss_crypto.h>
#include <libprxsocket/socket_ssr_auth.h>
#include <libprxsocket/socket_ssr_obfs.h>
#include <libprxsocket/crypto_cryptopp.h>

using namespace prxsocket;
using namespace prxsocket::socks5_helper;

#ifdef _MSC_VER
#pragma comment(lib, "cryptlib.lib")
#pragma comment(lib, "libprxsocket.lib")
#endif

#endif //PCH_H
