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

#include "pch.h"
#include "ServerConfigurationNodes.h"
#include "ServerConfigurationVisitor.h"

namespace
{

	template <typename Crypto, size_t KEY_LENGTH, size_t IV_LENGTH>
	class encryptor_cryptopp final : public prxsocket::encryptor
	{
		using encryptor_type = typename Crypto::Encryption;
		static constexpr size_t KEY_SIZE = KEY_LENGTH / 8;
		static constexpr size_t IV_SIZE = IV_LENGTH / 8;
	public:
		virtual size_t key_size() const override { return KEY_SIZE; }
		virtual size_t iv_size() const override { return IV_SIZE; }
		virtual const char *iv() const override { return (const char *)iv_; }
		virtual void set_key(const char *key) override
		{
			random_generator::random_bytes(iv_, sizeof(iv_));
			e_.SetKeyWithIV((const CryptoPP::byte *)key, KEY_SIZE, iv_);
		}
		virtual void set_key_iv(const char *key, const char *iv) override
		{
			memcpy(iv_, iv, sizeof(iv_));
			e_.SetKeyWithIV((const CryptoPP::byte *)key, KEY_SIZE, iv_);
		}

		virtual void encrypt(std::vector<char> &dst, const char *src, size_t src_size) override
		{
			CryptoPP::StringSource ss(
				(const CryptoPP::byte *)src, src_size,
				true,
				new CryptoPP::StreamTransformationFilter(
					e_,
					new CryptoPP::StringSinkTemplate<std::vector<char>>(dst)
				)
			);
		}
	private:
		encryptor_type e_;
		CryptoPP::byte iv_[IV_SIZE];
	};

	template <typename Crypto, size_t KEY_LENGTH, size_t IV_LENGTH>
	class decryptor_cryptopp final : public prxsocket::decryptor
	{
		using decryptor_type = typename Crypto::Decryption;
		static constexpr size_t KEY_SIZE = KEY_LENGTH / 8;
		static constexpr size_t IV_SIZE = IV_LENGTH / 8;
	public:
		virtual size_t key_size() const override { return KEY_SIZE; }
		virtual size_t iv_size() const override { return IV_SIZE; }
		virtual const char *iv() const override { return (const char *)iv_; }
		virtual void set_key(const char *key) override
		{
			random_generator::random_bytes(iv_, sizeof(iv_));
			d_.SetKeyWithIV((const CryptoPP::byte *)key, KEY_SIZE, iv_);
		}
		virtual void set_key_iv(const char *key, const char *iv) override
		{
			memcpy(iv_, iv, sizeof(iv_));
			d_.SetKeyWithIV((const CryptoPP::byte *)key, KEY_SIZE, iv_);
		}

		virtual void decrypt(std::vector<char> &dst, const char *src, size_t src_size) override
		{
			CryptoPP::StringSource ss(
				(const CryptoPP::byte *)src, src_size,
				true,
				new CryptoPP::StreamTransformationFilter(
					d_,
					new CryptoPP::StringSinkTemplate<std::vector<char>>(dst)
				)
			);
		}
	private:
		decryptor_type d_;
		CryptoPP::byte iv_[IV_SIZE];
	};

	template <typename Crypto, size_t KEY_LENGTH, size_t IV_LENGTH, size_t TAG_LENGTH>
	class encryptor_cryptopp_auth final : public prxsocket::encryptor
	{
		using encryptor_type = typename Crypto::Encryption;
		static constexpr size_t KEY_SIZE = KEY_LENGTH / 8;
		static constexpr size_t IV_SIZE = IV_LENGTH / 8;
		static constexpr size_t TAG_SIZE = TAG_LENGTH / 8;
	public:
		virtual size_t key_size() const override { return KEY_SIZE; }
		virtual size_t iv_size() const override { return IV_SIZE; }
		virtual const char *iv() const override { return (const char *)iv_; }
		virtual void set_key(const char *key) override
		{
			random_generator::random_bytes(iv_, sizeof(iv_));
			e_.SetKeyWithIV((const CryptoPP::byte *)key, KEY_SIZE, iv_);
		}
		virtual void set_key_iv(const char *key, const char *iv) override
		{
			memcpy(iv_, iv, sizeof(iv_));
			e_.SetKeyWithIV((const CryptoPP::byte *)key, KEY_SIZE, iv_);
		}

		virtual void encrypt(std::vector<char> &dst, const char *src, size_t src_size) override
		{
			CryptoPP::StringSource ss(
				(const CryptoPP::byte *)src, src_size,
				true,
				new CryptoPP::AuthenticatedEncryptionFilter(
					e_,
					new CryptoPP::StringSinkTemplate<std::vector<char>>(dst),
					false,
					TAG_SIZE
				)
			);
		}
	private:
		encryptor_type e_;
		CryptoPP::byte iv_[IV_SIZE];
	};

	template <typename Crypto, size_t KEY_LENGTH, size_t IV_LENGTH, size_t TAG_LENGTH>
	class decryptor_cryptopp_auth final : public prxsocket::decryptor
	{
		using decryptor_type = typename Crypto::Decryption;
		static constexpr size_t KEY_SIZE = KEY_LENGTH / 8;
		static constexpr size_t IV_SIZE = IV_LENGTH / 8;
		static constexpr size_t TAG_SIZE = TAG_LENGTH / 8;
	public:
		virtual size_t key_size() const override { return KEY_SIZE; }
		virtual size_t iv_size() const override { return IV_SIZE; }
		virtual const char *iv() const override { return (const char *)iv_; }
		virtual void set_key(const char *key) override
		{
			random_generator::random_bytes(iv_, sizeof(iv_));
			d_.SetKeyWithIV((const CryptoPP::byte *)key, KEY_SIZE, iv_);
		}
		virtual void set_key_iv(const char *key, const char *iv) override
		{
			memcpy(iv_, iv, sizeof(iv_));
			d_.SetKeyWithIV((const CryptoPP::byte *)key, KEY_SIZE, iv_);
		}

		virtual void decrypt(std::vector<char> &dst, const char *src, size_t src_size) override
		{
			CryptoPP::StringSource ss(
				(const CryptoPP::byte *)src, src_size,
				true,
				new CryptoPP::AuthenticatedDecryptionFilter(
					d_,
					new CryptoPP::StringSinkTemplate<std::vector<char>>(dst),
					CryptoPP::AuthenticatedDecryptionFilter::MAC_AT_END | CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
					TAG_SIZE
				)
			);
		}
	private:
		decryptor_type d_;
		CryptoPP::byte iv_[IV_SIZE];
	};

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

	std::vector<char> StringToSSKey(const std::string &password, const std::string &method)
	{
		static std::unordered_map<std::string, std::function<std::vector<char>(const std::string &)>> key_gens = {
			{"aes-128-ctr", [](const std::string &key)->std::vector<char> { return StringToSSKey<128 / 8>(key); }},
			{"aes-256-ctr", [](const std::string &key)->std::vector<char> { return StringToSSKey<256 / 8>(key); }},
			{"aes-128-cfb", [](const std::string &key)->std::vector<char> { return StringToSSKey<128 / 8>(key); }},
			{"aes-256-cfb", [](const std::string &key)->std::vector<char> { return StringToSSKey<256 / 8>(key); }},
		};
		try
		{
			return key_gens.at(method)(password);
		}
		catch (const std::out_of_range &)
		{
			throw std::invalid_argument("Invalid crypto method " + method);
		}
	}

	struct Cryptor
	{
		std::unique_ptr<encryptor> encryptor;
		std::unique_ptr<decryptor> decryptor;
	};

	template <typename BaseCrypto, size_t KeySize, size_t IvSize>
	Cryptor CryptoPPCryptoFactory()
	{
		return Cryptor{
			std::make_unique<encryptor_cryptopp<BaseCrypto, KeySize, IvSize>>(),
			std::make_unique<decryptor_cryptopp<BaseCrypto, KeySize, IvSize>>()
		};
	}

	Cryptor CryptoFactory(const std::string &method)
	{
		static std::unordered_map<std::string, std::function<Cryptor()>> factories = {
			{"aes-128-ctr", []()->Cryptor { return CryptoPPCryptoFactory<CryptoPP::CTR_Mode<CryptoPP::AES>, 128, 128>(); }},
			{"aes-256-ctr", []()->Cryptor { return CryptoPPCryptoFactory<CryptoPP::CTR_Mode<CryptoPP::AES>, 256, 128>(); }},
			{"aes-128-cfb", []()->Cryptor { return CryptoPPCryptoFactory<CryptoPP::CFB_Mode<CryptoPP::AES>, 128, 128>(); }},
			{"aes-256-cfb", []()->Cryptor { return CryptoPPCryptoFactory<CryptoPP::CFB_Mode<CryptoPP::AES>, 256, 128>(); }},
		};
		try
		{
			return factories.at(method)();
		}
		catch (const std::out_of_range &)
		{
			throw std::invalid_argument("Invalid crypto method " + method);
		}
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

void ObjectReferenceNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

void RawTcpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_tcp_socket> RawTcpSocketNode::NewTcpSocket()
{
	return std::make_unique<raw_tcp_socket>(io_context_);
}

void HttpTcpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_tcp_socket> HttpTcpSocketNode::NewTcpSocket()
{
	return std::make_unique<http_tcp_socket>(Base().NewTcpSocket(), server_endpoint_);
}

void Socks5TcpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_tcp_socket> Socks5TcpSocketNode::NewTcpSocket()
{
	return std::make_unique<socks5_tcp_socket>(Base().NewTcpSocket(), server_endpoint_);
}

ObfsWebsockTcpSocketNode::ObfsWebsockTcpSocketNode(ServerConfigurationNode *base, const std::string &password)
	:LayeredTcpSocketNode(base)
{
	CryptoPP::SHA256 hasher;
	CryptoPP::byte key_real[CryptoPP::SHA256::DIGESTSIZE];
	hasher.CalculateDigest(key_real, (CryptoPP::byte*)(password.data()), password.size());
	key_.assign((const char*)key_real, sizeof(key_real));
}

void ObfsWebsockTcpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_tcp_socket> ObfsWebsockTcpSocketNode::NewTcpSocket()
{
	return std::make_unique<obfs_websock_tcp_socket>(Base().NewTcpSocket(), key_);
}

void SSTcpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_tcp_socket> SSTcpSocketNode::NewTcpSocket()
{
	return std::make_unique<ss::ss_tcp_socket>(Base().NewTcpSocket(), server_endpoint_);
}

SSCryptoTcpSocketNode::SSCryptoTcpSocketNode(ServerConfigurationNode *base, const std::string &method, const std::string &password)
	:LayeredTcpSocketNode(base), method_(method), key_(StringToSSKey(password, method))
{
}

std::unique_ptr<ss::ss_crypto_tcp_socket> SSCryptoTcpSocketNode::NewSSCryptoTcpSocket()
{
	Cryptor cryptor = CryptoFactory(method_);
	return std::make_unique<ss::ss_crypto_tcp_socket>(Base().NewTcpSocket(), key_, std::move(cryptor.encryptor), std::move(cryptor.decryptor));
}

void SSCryptoTcpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_tcp_socket> SSCryptoTcpSocketNode::NewTcpSocket()
{
	return NewSSCryptoTcpSocket();
}

void SSRAuthAes128Sha1TcpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_tcp_socket> SSRAuthAes128Sha1TcpSocketNode::NewTcpSocket()
{
	return std::make_unique<ssr::ssr_auth_aes128_sha1_tcp_socket>(Base().NewSSCryptoTcpSocket(), GetSSRAuthAes128Sha1SharedServerData(param_));
}

void SSRHttpSimpleTcpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_tcp_socket> SSRHttpSimpleTcpSocketNode::NewTcpSocket()
{
	return std::make_unique<ssr::ssr_http_simple_tcp_socket>(Base().NewTcpSocket(), param_);
}

void RawUdpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_udp_socket> RawUdpSocketNode::NewUdpSocket()
{
	return std::make_unique<raw_udp_socket>(io_context_);
}

void Socks5UdpSocketNode::Validate() const
{
	if (dynamic_cast<TcpSocketNode *>(base_) == nullptr)
		throw std::invalid_argument("Invalid base for base of Socks5UdpSocket");
	if (udp_base_ && dynamic_cast<UdpSocketNode *>(udp_base_) == nullptr)
		throw std::invalid_argument("Invalid base for udp base of Socks5UdpSocket");
}

void Socks5UdpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_udp_socket> Socks5UdpSocketNode::NewUdpSocket()
{
	if (udp_base_)
		return std::make_unique<socks5_udp_socket>(static_cast<TcpSocketNode *>(base_)->NewTcpSocket(), static_cast<UdpSocketNode *>(udp_base_)->NewUdpSocket(), server_endpoint_);
	else
		return std::make_unique<socks5_udp_socket>(static_cast<TcpSocketNode *>(base_)->NewTcpSocket(), server_endpoint_);
}

void SSUdpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

SSCryptoUdpSocketNode::SSCryptoUdpSocketNode(ServerConfigurationNode *base, const std::string &method, const std::string &password)
	:LayeredUdpSocketNode(base), method_(method), key_(StringToSSKey(password, method))
{
}

std::unique_ptr<ss::ss_crypto_udp_socket> SSCryptoUdpSocketNode::NewSSCryptoUdpSocket()
{
	Cryptor cryptor = CryptoFactory(method_);
	return std::make_unique<ss::ss_crypto_udp_socket>(Base().NewUdpSocket(), key_, std::move(cryptor.encryptor), std::move(cryptor.decryptor));
}

void SSCryptoUdpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_udp_socket> SSCryptoUdpSocketNode::NewUdpSocket()
{
	return NewSSCryptoUdpSocket();
}

void RawListenerNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_listener> RawListenerNode::NewListener()
{
	return std::make_unique<raw_listener>(io_context_);
}

void Socks5ListenerNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_listener> Socks5ListenerNode::NewListener()
{
	return std::make_unique<socks5_listener>([this]() { return Base().NewTcpSocket(); }, server_endpoint_);
}

ObfsWebsockListenerNode::ObfsWebsockListenerNode(ServerConfigurationNode *base, const std::string &password)
	:LayeredListenerNode(base)
{
	CryptoPP::SHA256 hasher;
	CryptoPP::byte key_real[CryptoPP::SHA256::DIGESTSIZE];
	hasher.CalculateDigest(key_real, (CryptoPP::byte*)(password.data()), password.size());
	key_.assign((const char*)key_real, sizeof(key_real));
}

void ObfsWebsockListenerNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_listener> ObfsWebsockListenerNode::NewListener()
{
	return std::make_unique<obfs_websock_listener>(Base().NewListener(), key_);
}

RootNode::RootNode(
	int thread_count,
	const endpoint &upstream_local_endpoint,
	ServerConfigurationNode *upstream_listener,
	ServerConfigurationNode *upstream_udp_socket,
	ServerConfigurationNode *downstream_tcp_socket,
	ServerConfigurationNode *downstream_udp_socket,
	ServerConfigurationNode *downstream_listener
)
	:thread_count_(thread_count),
	upstream_local_endpoint_(upstream_local_endpoint),
	downstream_tcp_socket_(downstream_tcp_socket),
	upstream_udp_socket_(upstream_udp_socket),
	downstream_udp_socket_(downstream_udp_socket),
	upstream_listener_(upstream_listener),
	downstream_listener_(downstream_listener)
{
}

void RootNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

void RootNode::Validate() const
{
	if (thread_count_ < 1 || thread_count_ > 16)
		throw std::invalid_argument("Invalid thread count");
	if (dynamic_cast<TcpSocketNode *>(downstream_tcp_socket_) == nullptr)
		throw std::invalid_argument("Invalid downstream tcp socket");
	if (dynamic_cast<UdpSocketNode *>(upstream_udp_socket_) == nullptr)
		throw std::invalid_argument("Invalid upstream udp socket");
	if (dynamic_cast<UdpSocketNode *>(downstream_udp_socket_) == nullptr)
		throw std::invalid_argument("Invalid downstream udp socket");
	if (dynamic_cast<ListenerNode *>(upstream_listener_) == nullptr)
		throw std::invalid_argument("Invalid upstream listener");
	if (dynamic_cast<ListenerNode *>(downstream_listener_) == nullptr)
		throw std::invalid_argument("Invalid downstream listener");
}
