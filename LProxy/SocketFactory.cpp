#include "pch.h"
#include "SocketFactory.h"

namespace {
	template <size_t N>
	void StringToSSKey(char(&dst)[N], const char *src, size_t src_size)
	{
		static_assert(N > 0 && N % 16 == 0, "str_to_key doesn't support dst with any size");
		CryptoPP::MD5 md5;

		size_t i = 0;
		while (i < N)
		{
			if (i == 0)
			{
				md5.CalculateDigest((CryptoPP::byte *)dst, (const CryptoPP::byte *)src, src_size);
			}
			else
			{
				md5.Update((const CryptoPP::byte *)dst + i - md5.DIGESTSIZE, md5.DIGESTSIZE);
				md5.Update((const CryptoPP::byte *)src, src_size);
				md5.Final((CryptoPP::byte *)dst + i);
			}
			i += md5.DIGESTSIZE;
		}
	}

	template <size_t N>
	std::vector<char> StringToSSKey(const std::string &key)
	{
		char keyBuffer[N];
		StringToSSKey(keyBuffer, key.data(), key.size());
		return std::vector<char>(keyBuffer, keyBuffer + N);
	}

	struct CryptoData
	{
		std::vector<char> key;
		std::unique_ptr<encryptor> encryptor;
		std::unique_ptr<decryptor> decryptor;
	};

	template <typename BaseCrypto, size_t KeySize, size_t IvSize>
	CryptoData CryptoPPCryptoFactory(const std::string key)
	{
		return CryptoData{
			StringToSSKey<KeySize / 8>(key),
			std::make_unique<encryptor_cryptopp<BaseCrypto, KeySize, IvSize>>(),
			std::make_unique<decryptor_cryptopp<BaseCrypto, KeySize, IvSize>>()
		};
	}

	CryptoData CryptoFactory(const std::string &name, const std::string &keyString)
	{
		static std::unordered_map<std::string, std::function<CryptoData(const std::string &)>> factories = {
			{"aes-128-ctr", [](const std::string &key)->CryptoData { return CryptoPPCryptoFactory<CryptoPP::CTR_Mode<CryptoPP::AES>, 128, 128>(key); }},
			{"aes-256-ctr", [](const std::string &key)->CryptoData { return CryptoPPCryptoFactory<CryptoPP::CTR_Mode<CryptoPP::AES>, 256, 128>(key); }},
			{"aes-128-cfb", [](const std::string &key)->CryptoData { return CryptoPPCryptoFactory<CryptoPP::CFB_Mode<CryptoPP::AES>, 128, 128>(key); }},
			{"aes-256-cfb", [](const std::string &key)->CryptoData { return CryptoPPCryptoFactory<CryptoPP::CFB_Mode<CryptoPP::AES>, 256, 128>(key); }},
		};
		return factories.at(name)(keyString);
	}

	ssr::ssr_auth_aes128_sha1_shared_server_data &GetSSRAuthAes128Sha1SharedServerData(const std::string &arg)
	{
		static std::unordered_map<std::string, ssr::ssr_auth_aes128_sha1_shared_server_data> args;
		static std::mutex mutex;
		std::lock_guard<std::mutex> lock(mutex);
		if (args.count(arg) == 0)
			return args.emplace(arg, arg).first->second;
		return args.at(arg);
	}
}

endpoint SocketFactory::StringToEndpoint(const std::string &str, port_type default_port)
{
	size_t pos_addr_begin = str.find_first_of('[');
	if (pos_addr_begin != std::string::npos)
	{
		pos_addr_begin = pos_addr_begin + 1;
		size_t pos_addr_end = str.find_first_of(']', pos_addr_begin);
		if (pos_addr_end == std::string::npos)
			throw std::runtime_error("Invalid string for endpoint");
		size_t pos_port_begin = str.find_first_of(':', pos_addr_end + 1);
		if (pos_port_begin != std::string::npos)
			return endpoint(str.substr(pos_addr_begin, pos_addr_end - pos_addr_begin), (port_type)std::stoi(str.substr(pos_port_begin + 1)));
		else
			return endpoint(str.substr(pos_addr_begin, pos_addr_end - pos_addr_begin), default_port);
	}
	else
	{
		size_t pos_port_begin = str.find_first_of(':');
		if (pos_port_begin != std::string::npos)
			return endpoint(str.substr(0, pos_port_begin), (port_type)std::stoi(str.substr(pos_port_begin + 1)));
		else
			return endpoint(str, default_port);
	}
}

endpoint SocketFactory::StringToEndpointWithResolve(const std::string &str, port_type default_port, asio::io_context &ioContext)
{
	asio::ip::tcp::resolver resolver(ioContext);
	asio::ip::tcp::endpoint resolved_ep;

	size_t pos_addr_begin = str.find_first_of('[');
	if (pos_addr_begin != std::string::npos)
	{
		pos_addr_begin = pos_addr_begin + 1;
		size_t pos_addr_end = str.find_first_of(']', pos_addr_begin);
		if (pos_addr_end == std::string::npos)
			throw std::runtime_error("Invalid string for endpoint");
		size_t pos_port_begin = str.find_first_of(':', pos_addr_end + 1);
		if (pos_port_begin != std::string::npos)
			resolved_ep = resolver.resolve({ str.substr(pos_addr_begin, pos_addr_end - pos_addr_begin), str.substr(pos_port_begin + 1) })->endpoint();
		else
			resolved_ep = resolver.resolve({ str.substr(pos_addr_begin, pos_addr_end - pos_addr_begin), std::to_string(default_port) })->endpoint();
	}
	else
	{
		size_t pos_port_begin = str.find_last_of(':');
		if (pos_port_begin != std::string::npos)
			resolved_ep = resolver.resolve({ str.substr(0, pos_port_begin), str.substr(pos_port_begin + 1) })->endpoint();
		else
			resolved_ep = resolver.resolve({ str, std::to_string(default_port) })->endpoint();
	}

	const asio::ip::address &resolved_addr = resolved_ep.address();
	if (resolved_addr.is_v4())
		return endpoint(resolved_addr.to_v4().to_ulong(), resolved_ep.port());
	else if (resolved_addr.is_v6())
		return endpoint(address_v6(resolved_addr.to_v6().to_bytes().data()), resolved_ep.port());
	else
		return endpoint(resolved_addr.to_string(), resolved_ep.port());
}

std::unique_ptr<prx_tcp_socket> SocketFactory::LoadTcpSocket(const ptree::ptree &args, asio::io_context &ioContext)
{
	static std::unordered_map<std::string, std::function<std::unique_ptr<prx_tcp_socket>(const ptree::ptree &, asio::io_context &)>> factories = {
		{"raw", [](const ptree::ptree &args, asio::io_context &ioCtx)->std::unique_ptr<prx_tcp_socket>
			{
				return std::make_unique<raw_tcp_socket>(ioCtx);
			}
		},
		{"http", [](const ptree::ptree &args, asio::io_context &ioCtx)->std::unique_ptr<prx_tcp_socket>
			{
				return std::make_unique<http_tcp_socket>(
					StringToEndpoint(args.get<std::string>("server"), 8080),
					LoadTcpSocket(args.get_child("parent"), ioCtx)
					);
			}
		},
		{"socks5", [](const ptree::ptree &args, asio::io_context &ioCtx)->std::unique_ptr<prx_tcp_socket>
			{
				return std::make_unique<socks5_tcp_socket>(
					StringToEndpoint(args.get<std::string>("server"), 1080),
					LoadTcpSocket(args.get_child("parent"), ioCtx)
					);
			}
		},
		{"obfs_websock", [](const ptree::ptree &args, asio::io_context &ioCtx)->std::unique_ptr<prx_tcp_socket>
			{
				CryptoPP::SHA256 hasher;
				CryptoPP::byte key_real[CryptoPP::SHA256::DIGESTSIZE];
				const std::string &key_string = args.get<std::string>("key");
				hasher.CalculateDigest(key_real, (CryptoPP::byte*)(key_string.data()), key_string.size());
				return std::make_unique<obfs_websock_tcp_socket>(
					LoadTcpSocket(args.get_child("parent"), ioCtx),
					std::string((const char*)key_real, sizeof(key_real))
					);
			}
		},
		{"ss", [](const ptree::ptree &args, asio::io_context &ioCtx)->std::unique_ptr<prx_tcp_socket>
			{
				return std::make_unique<ss::ss_tcp_socket>(
					StringToEndpoint(args.get<std::string>("server"), 1080),
					LoadTcpSocket(args.get_child("parent"), ioCtx)
					);
			}
		},
		{"ss_crypto", [](const ptree::ptree &args, asio::io_context &ioCtx)->std::unique_ptr<prx_tcp_socket>
			{
				CryptoData cryptoData = CryptoFactory(args.get<std::string>("method"), args.get<std::string>("password"));
				return std::make_unique<ss::ss_crypto_tcp_socket>(
					LoadTcpSocket(args.get_child("parent"), ioCtx),
					cryptoData.key,
					std::move(cryptoData.encryptor),
					std::move(cryptoData.decryptor)
					);
			}
		},
		{"ssr_auth_aes128_sha1", [](const ptree::ptree &args, asio::io_context &ioCtx)->std::unique_ptr<prx_tcp_socket>
			{
				CryptoData cryptoData = CryptoFactory(args.get<std::string>("method"), args.get<std::string>("password"));
				return std::make_unique<ssr::ssr_auth_aes128_sha1_tcp_socket>(
					std::make_unique<ss::ss_crypto_tcp_socket>(
						LoadTcpSocket(args.get_child("parent"), ioCtx),
						cryptoData.key,
						std::move(cryptoData.encryptor),
						std::move(cryptoData.decryptor)
						),
					GetSSRAuthAes128Sha1SharedServerData(args.get<std::string>("param"))
					);
			}
		},
		{"ssr_http_simple", [](const ptree::ptree &args, asio::io_context &ioCtx)->std::unique_ptr<prx_tcp_socket>
			{
				return std::make_unique<ssr::ssr_http_simple_tcp_socket>(
					LoadTcpSocket(args.get_child("parent"), ioCtx),
					args.get<std::string>("param")
					);
			}
		},
	};
	return factories.at(args.get<std::string>("type"))(args, ioContext);
}

std::unique_ptr<prx_udp_socket> SocketFactory::LoadUdpSocket(const ptree::ptree &args, asio::io_context &ioContext)
{
	static std::unordered_map<std::string, std::function<std::unique_ptr<prx_udp_socket>(const ptree::ptree &, asio::io_context &)>> factories = {
		{"raw", [](const ptree::ptree &args, asio::io_context &ioCtx)->std::unique_ptr<prx_udp_socket>
			{
				return std::make_unique<raw_udp_socket>(ioCtx);
			}
		},
		{"socks5", [](const ptree::ptree &args, asio::io_context &ioCtx)->std::unique_ptr<prx_udp_socket>
			{
				if (args.count("parent") == 0)
					return std::make_unique<socks5_udp_socket>(
						StringToEndpoint(args.get<std::string>("server"), 1080),
						LoadTcpSocket(args.get_child("parent_tcp"), ioCtx)
						);
				else
					return std::make_unique<socks5_udp_socket>(
						StringToEndpoint(args.get<std::string>("server"), 1080),
						LoadTcpSocket(args.get_child("parent_tcp"), ioCtx),
						LoadUdpSocket(args.get_child("parent"), ioCtx)
						);
			}
		},
		{"ss", [](const ptree::ptree &args, asio::io_context &ioCtx)->std::unique_ptr<prx_udp_socket>
			{
				return std::make_unique<ss::ss_udp_socket>(
					StringToEndpoint(args.get<std::string>("server"), 1080),
					LoadUdpSocket(args.get_child("parent"), ioCtx)
					);
			}
		},
		{"ss_crypto", [](const ptree::ptree &args, asio::io_context &ioCtx)->std::unique_ptr<prx_udp_socket>
			{
				CryptoData cryptoData = CryptoFactory(args.get<std::string>("method"), args.get<std::string>("password"));
				return std::make_unique<ss::ss_crypto_udp_socket>(
					LoadUdpSocket(args.get_child("parent"), ioCtx),
					cryptoData.key,
					std::move(cryptoData.encryptor),
					std::move(cryptoData.decryptor)
					);
			}
		},
	};
	return factories.at(args.get<std::string>("type"))(args, ioContext);
}

std::unique_ptr<prx_listener> SocketFactory::LoadListener(const ptree::ptree &args, asio::io_context &ioContext)
{
	static std::unordered_map<std::string, std::function<std::unique_ptr<prx_listener>(const ptree::ptree &, asio::io_context &)>> factories = {
		{"raw", [](const ptree::ptree &args, asio::io_context &ioCtx)->std::unique_ptr<prx_listener>
			{
				return std::make_unique<raw_listener>(ioCtx);
			}
		},
		{"socks5", [](const ptree::ptree &args, asio::io_context &ioCtx)->std::unique_ptr<prx_listener>
			{
				return std::make_unique<socks5_listener>(
					StringToEndpoint(args.get<std::string>("server"), 1080),
					[parent_connection_args = args.get_child("parent_connection"), &ioCtx]() { return LoadTcpSocket(parent_connection_args, ioCtx); }
					);
			}
		},
		{"obfs_websock", [](const ptree::ptree &args, asio::io_context &ioCtx)->std::unique_ptr<prx_listener>
			{
				CryptoPP::SHA256 hasher;
				CryptoPP::byte key_real[CryptoPP::SHA256::DIGESTSIZE];
				const std::string &key_string = args.get<std::string>("key");
				hasher.CalculateDigest(key_real, (CryptoPP::byte*)(key_string.data()), key_string.size());
				return std::make_unique<obfs_websock_listener>(
					LoadListener(args.get_child("parent"), ioCtx),
					std::string((const char*)key_real, sizeof(key_real))
					);
			}
		},
	};
	return factories.at(args.get<std::string>("type"))(args, ioContext);
}
