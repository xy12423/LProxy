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

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/chachapoly.h>
#include <cryptopp/modes.h>
#include <cryptopp/md5.h>

#include <libprxsocket/socket_raw.h>
#include <libprxsocket/socket_http.h>
#include <libprxsocket/socket_socks5.h>
#include <libprxsocket/socket_obfs_websock.h>
#include <libprxsocket/socket_ss.h>
#include <libprxsocket/socket_ss_crypto.h>
#include <libprxsocket/socket_ssr_auth.h>
#include <libprxsocket/socket_ssr_obfs.h>
#include <libprxsocket/socket_vmess.h>
#include <libprxsocket/random_generator.h>

using namespace prxsocket;
using namespace prxsocket::socks5_helper;

#ifdef _MSC_VER
#pragma comment(lib, "cryptlib.lib")
#pragma comment(lib, "libprxsocket.lib")
#endif

#endif //PCH_H
