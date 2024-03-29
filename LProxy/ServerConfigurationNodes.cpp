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

	using namespace CryptoPP;

	class MultipleBufferStore : public Store
	{
	public:
		MultipleBufferStore() {}
		MultipleBufferStore(const_buffer_sequence *buffer, size_t buffer_read_size)
			:buffer_(buffer), buffer_read_size_(buffer_read_size)
		{
			assert(buffer_read_size_ <= buffer_->size_total());
		}

		bool AnyRetrievable() const { return MaxRetrievable() != 0; }
		lword MaxRetrievable() const { return buffer_read_size_; }

		size_t TransferTo2(BufferedTransformation &target, lword &transferBytes, const std::string &channel = DEFAULT_CHANNEL, bool blocking = true)
		{
			size_t transfer_plan = std::min(transferBytes, buffer_read_size_);

			size_t transfer_last = transfer_plan;
			size_t blocked_bytes = 0;
			while (transfer_last > 0)
			{
				const_buffer current = buffer_->front();
				if (transfer_last >= current.size())
				{
					blocked_bytes = target.ChannelPut2(channel, (const byte *)current.data(), current.size(), 0, blocking);
					if (blocked_bytes)
						break;
					transfer_last -= current.size();
					buffer_->pop_front();
				}
				else
				{
					blocked_bytes = target.ChannelPut2(channel, (const byte *)current.data(), transfer_last, 0, blocking);
					if (blocked_bytes)
						break;
					buffer_->consume_front(transfer_last);
					transfer_last = 0;
					break;
				}
			}

			size_t transferred_bytes = transfer_plan - transfer_last;
			buffer_read_size_ -= transferred_bytes;
			transferBytes = transferred_bytes;
			return blocked_bytes;
		}
		size_t CopyRangeTo2(BufferedTransformation &target, lword &begin, lword end = LWORD_MAX, const std::string &channel = DEFAULT_CHANNEL, bool blocking = true) const
		{
			CRYPTOPP_UNUSED(target); CRYPTOPP_UNUSED(begin); CRYPTOPP_UNUSED(end); CRYPTOPP_UNUSED(channel); CRYPTOPP_UNUSED(blocking);
			throw NotImplemented("MultipleBufferStore: CopyRangeTo2() is not supported by this store");
		}
	private:
		void StoreInitialize(const NameValuePairs &parameters)
		{
			if (!parameters.GetValue("InputBuffer", buffer_))
				throw InvalidArgument("MultipleBufferSource: InputBuffer not specified");
			if (!parameters.GetValue("InputReadSize", buffer_read_size_))
				throw InvalidArgument("MultipleBufferSource: InputReadSize not specified");
		}

		const_buffer_sequence *buffer_ = nullptr;
		size_t buffer_read_size_ = 0;
	};

	class MultipleBufferSource : public SourceTemplate<MultipleBufferStore>
	{
	public:
		MultipleBufferSource(const_buffer_sequence &buffer, size_t buffer_read_size, bool pumpAll, BufferedTransformation *attachment = NULLPTR)
			:SourceTemplate<MultipleBufferStore>(attachment)
		{
			SourceInitialize(pumpAll, MakeParameters("InputBuffer", &buffer)("InputReadSize", buffer_read_size));
		}
	};

	class SingleBufferAndVectorSink : public Bufferless<Sink>
	{
	public:
		virtual ~SingleBufferAndVectorSink() = default;

		SingleBufferAndVectorSink(mutable_buffer buffer_1, std::vector<char> &buffer_2, size_t &buffer_1_usage)
			:buffer_1_(buffer_1), buffer_2_(&buffer_2), buffer_1_usage_(&buffer_1_usage)
		{
		}

		void IsolatedInitialize(const NameValuePairs &parameters)
		{
			char *buffer_1_data;
			size_t buffer_1_size;
			if (!parameters.GetValue("OutputBuffer1Pointer", buffer_1_data))
				throw InvalidArgument("SingleBufferAndVectorSink: OutputBuffer1Pointer not specified");
			if (!parameters.GetValue("OutputBuffer1Size", buffer_1_size))
				throw InvalidArgument("SingleBufferAndVectorSink: OutputBuffer1Size not specified");
			if (!parameters.GetValue("OutputBuffer1Usage", buffer_1_usage_))
				throw InvalidArgument("SingleBufferAndVectorSink: OutputBuffer1Usage not specified");
			if (!parameters.GetValue("OutputBuffer2Pointer", buffer_2_))
				throw InvalidArgument("SingleBufferAndVectorSink: OutputBuffer2Pointer not specified");
			buffer_1_ = mutable_buffer(buffer_1_data, buffer_1_size);
		}

		size_t Put2(const byte *inString, size_t length, int messageEnd, bool blocking)
		{
			CRYPTOPP_UNUSED(messageEnd); CRYPTOPP_UNUSED(blocking);
			if (length == 0)
				return 0;
			if (buffer_1_.size() != 0)
			{
				size_t copying = std::min(buffer_1_.size(), length);
				memcpy(buffer_1_.data(), inString, copying);
				buffer_1_ = mutable_buffer(buffer_1_.data() + copying, buffer_1_.size() - copying);
				*buffer_1_usage_ += copying;
				if (length == copying)
					return 0;
				inString += copying;
				length -= copying;
			}
			std::vector<char>::size_type size = buffer_2_->size();
			if (length < size && size + length > buffer_2_->capacity())
				buffer_2_->reserve(2 * size);
			buffer_2_->insert(buffer_2_->end(), (const char *)inString, (const char *)inString + length);
			return 0;
		}

	private:
		mutable_buffer buffer_1_;
		std::vector<char> *buffer_2_ = nullptr;
		size_t *buffer_1_usage_ = nullptr;
	};

	class MultipleBufferAndVectorSink : public Bufferless<Sink>
	{
	public:
		virtual ~MultipleBufferAndVectorSink() = default;

		MultipleBufferAndVectorSink(mutable_buffer_sequence &buffer_1, std::vector<char> &buffer_2)
			: buffer_1_(&buffer_1), buffer_2_(&buffer_2)
		{
		}

		void IsolatedInitialize(const NameValuePairs &parameters)
		{
			if (!parameters.GetValue("OutputBuffer1Pointer", buffer_1_))
				throw InvalidArgument("MultipleBufferAndVectorSink: OutputBuffer1Pointer not specified");
			if (!parameters.GetValue("OutputBuffer2Pointer", buffer_2_))
				throw InvalidArgument("MultipleBufferAndVectorSink: OutputBuffer2Pointer not specified");
		}

		size_t Put2(const byte *inString, size_t length, int messageEnd, bool blocking)
		{
			CRYPTOPP_UNUSED(messageEnd); CRYPTOPP_UNUSED(blocking);
			if (length == 0)
				return 0;
			if (!buffer_1_->empty())
			{
				size_t copied = buffer_1_->scatter((const char *)inString, length);
				if (length == copied)
					return 0;
				inString += copied;
				length -= copied;
			}
			std::vector<char>::size_type size = buffer_2_->size();
			if (length < size && size + length > buffer_2_->capacity())
				buffer_2_->reserve(2 * size);
			buffer_2_->insert(buffer_2_->end(), (const char *)inString, (const char *)inString + length);
			return 0;
		}

	private:
		mutable_buffer_sequence *buffer_1_ = nullptr;
		std::vector<char> *buffer_2_ = nullptr;
	};

	class encryptor_plain final : public prxsocket::encryptor
	{
	public:
		virtual size_t key_size() const override { return 0; }
		virtual size_t iv_size() const override { return 0; }
		virtual const char *iv() const override { return nullptr; }
		virtual void set_key(const char *key) override {}
		virtual void set_key_iv(const char *key, const char *iv) override {}
		virtual void encrypt(std::vector<char> &dst, const char *src, size_t src_size) override
		{
			dst.insert(dst.end(), src, src + src_size);
		}
		virtual void encrypt(std::vector<char> &dst, const_buffer_sequence &src, size_t src_size) override
		{
			size_t size_total = 0;
			while (!src.empty())
			{
				const_buffer next = src.front();
				if (size_total + next.size() <= src_size)
				{
					dst.insert(dst.end(), next.data(), next.data() + next.size());
					src.pop_front();
				}
				else
				{
					size_t extra_size = src_size - size_total;
					dst.insert(dst.end(), next.data(), next.data() + extra_size);
					src.consume_front(extra_size);
					break;
				}
			}
		}
	};

	class decryptor_plain final : public prxsocket::decryptor
	{
	public:
		virtual size_t key_size() const override { return 0; }
		virtual size_t iv_size() const override { return 0; }
		virtual const char *iv() const override { return nullptr; }
		virtual void set_key(const char *key) override {}
		virtual void set_key_iv(const char *key, const char *iv) override {}
		virtual void decrypt(std::vector<char> &dst, const char *src, size_t src_size) override
		{
			dst.insert(dst.end(), src, src + src_size);
		}
		virtual size_t decrypt(mutable_buffer dst, std::vector<char> &dst_last, const char *src, size_t src_size)
		{
			if (dst.size() >= src_size)
			{
				memcpy(dst.data(), src, src_size);
				return src_size;
			}
			else
			{
				memcpy(dst.data(), src, dst.size());
				dst_last.insert(dst_last.end(), src + dst.size(), src + src_size - dst.size());
				return dst.size();
			}
		}
		virtual void decrypt(mutable_buffer_sequence &dst, std::vector<char> &dst_last, const char *src, size_t src_size)
		{
			size_t copied = dst.scatter(src, src_size);
			if (src_size > copied)
			{
				dst_last.insert(dst_last.end(), src + copied, src + src_size - copied);
			}
		}
	};

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
			e_.SetKeyWithIV((const byte *)key, KEY_SIZE, iv_);
		}
		virtual void set_key_iv(const char *key, const char *iv) override
		{
			memcpy(iv_, iv, sizeof(iv_));
			e_.SetKeyWithIV((const byte *)key, KEY_SIZE, iv_);
		}

		virtual void encrypt(std::vector<char> &dst, const char *src, size_t src_size) override
		{
			StringSource ss(
				(const byte *)src, src_size,
				true,
				new StreamTransformationFilter(
					e_,
					new StringSinkTemplate<std::vector<char>>(dst)
				)
			);
		}
		virtual void encrypt(std::vector<char> &dst, const_buffer_sequence &src, size_t src_size) override
		{
			MultipleBufferSource mbs(
				src, src_size,
				true,
				new StreamTransformationFilter(
					e_,
					new StringSinkTemplate<std::vector<char>>(dst)
				)
			);
		}
	private:
		encryptor_type e_;
		byte iv_[IV_SIZE];
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
			d_.SetKeyWithIV((const byte *)key, KEY_SIZE, iv_);
		}
		virtual void set_key_iv(const char *key, const char *iv) override
		{
			memcpy(iv_, iv, sizeof(iv_));
			d_.SetKeyWithIV((const byte *)key, KEY_SIZE, iv_);
		}

		virtual void decrypt(std::vector<char> &dst, const char *src, size_t src_size) override
		{
			StringSource ss(
				(const byte *)src, src_size,
				true,
				new StreamTransformationFilter(
					d_,
					new StringSinkTemplate<std::vector<char>>(dst)
				)
			);
		}
		virtual size_t decrypt(mutable_buffer dst, std::vector<char> &dst_last, const char *src, size_t src_size)
		{
			size_t dst_used = 0;
			StringSource ss(
				(const byte *)src, src_size,
				true,
				new StreamTransformationFilter(
					d_,
					new SingleBufferAndVectorSink(dst, dst_last, dst_used)
				)
			);
			return dst_used;
		}
		virtual void decrypt(mutable_buffer_sequence &dst, std::vector<char> &dst_last, const char *src, size_t src_size)
		{
			StringSource ss(
				(const byte *)src, src_size,
				true,
				new StreamTransformationFilter(
					d_,
					new MultipleBufferAndVectorSink(dst, dst_last)
				)
			);
		}
	private:
		decryptor_type d_;
		byte iv_[IV_SIZE];
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
			e_.SetKeyWithIV((const byte *)key, KEY_SIZE, iv_);
		}
		virtual void set_key_iv(const char *key, const char *iv) override
		{
			memcpy(iv_, iv, sizeof(iv_));
			e_.SetKeyWithIV((const byte *)key, KEY_SIZE, iv_);
		}

		virtual void encrypt(std::vector<char> &dst, const char *src, size_t src_size) override
		{
			StringSource ss(
				(const byte *)src, src_size,
				true,
				new AuthenticatedEncryptionFilter(
					e_,
					new StringSinkTemplate<std::vector<char>>(dst),
					false,
					TAG_SIZE
				)
			);
		}
		virtual void encrypt(std::vector<char> &dst, const_buffer_sequence &src, size_t src_size) override
		{
			MultipleBufferSource mbs(
				src, src_size,
				true,
				new AuthenticatedEncryptionFilter(
					e_,
					new StringSinkTemplate<std::vector<char>>(dst),
					false,
					TAG_SIZE
				)
			);
			/*
			AuthenticatedEncryptionFilter encryption(
				e_,
				new StringSinkTemplate<std::vector<char>>(dst),
				false,
				TAG_SIZE
			);
			size_t size_total = 0;
			while (!src.empty())
			{
				const_buffer next = src.front();
				if (size_total + next.size() <= src_size)
				{
					StringSource next_src((const byte *)next.data(), next.size(), false);
					next_src.Attach(new Redirector(encryption));
					next_src.Pump();
					next_src.Detach();
					src.pop_front();
				}
				else
				{
					size_t extra_size = src_size - size_total;
					StringSource next_src((const byte *)next.data(), extra_size, false);
					next_src.Attach(new Redirector(encryption));
					next_src.Pump();
					next_src.Detach();
					src.consume_front(extra_size);
					break;
				}
			}
			encryption.MessageEnd();
			*/
		}
	private:
		encryptor_type e_;
		byte iv_[IV_SIZE];
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
			d_.SetKeyWithIV((const byte *)key, KEY_SIZE, iv_);
		}
		virtual void set_key_iv(const char *key, const char *iv) override
		{
			memcpy(iv_, iv, sizeof(iv_));
			d_.SetKeyWithIV((const byte *)key, KEY_SIZE, iv_);
		}

		virtual void decrypt(std::vector<char> &dst, const char *src, size_t src_size) override
		{
			StringSource ss(
				(const byte *)src, src_size,
				true,
				new AuthenticatedDecryptionFilter(
					d_,
					new StringSinkTemplate<std::vector<char>>(dst),
					AuthenticatedDecryptionFilter::MAC_AT_END | AuthenticatedDecryptionFilter::THROW_EXCEPTION,
					TAG_SIZE
				)
			);
		}
		virtual size_t decrypt(mutable_buffer dst, std::vector<char> &dst_last, const char *src, size_t src_size)
		{
			size_t dst_used = 0;
			StringSource ss(
				(const byte *)src, src_size,
				true,
				new AuthenticatedDecryptionFilter(
					d_,
					new SingleBufferAndVectorSink(dst, dst_last, dst_used),
					AuthenticatedDecryptionFilter::MAC_AT_END | AuthenticatedDecryptionFilter::THROW_EXCEPTION,
					TAG_SIZE
				)
			);
			return dst_used;
		}
		virtual void decrypt(mutable_buffer_sequence &dst, std::vector<char> &dst_last, const char *src, size_t src_size)
		{
			StringSource ss(
				(const byte *)src, src_size,
				true,
				new AuthenticatedDecryptionFilter(
					d_,
					new MultipleBufferAndVectorSink(dst, dst_last),
					AuthenticatedDecryptionFilter::MAC_AT_END | AuthenticatedDecryptionFilter::THROW_EXCEPTION,
					TAG_SIZE
				)
			);
		}
	private:
		decryptor_type d_;
		byte iv_[IV_SIZE];
	};

	template <size_t N>
	void StringToSSKey(char(&dst)[N], const char *src, size_t src_size)
	{
		static_assert(N > 0 && N % 16 == 0, "str_to_key doesn't support dst with any size");
		Weak::MD5 md5;

		size_t i = 0;
		while (i < N)
		{
			if (i == 0)
			{
				md5.CalculateDigest((byte *)dst, (const byte *)src, src_size);
			}
			else
			{
				md5.Update((const byte *)dst + i - md5.DIGESTSIZE, md5.DIGESTSIZE);
				md5.Update((const byte *)src, src_size);
				md5.Final((byte *)dst + i);
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
		static const std::unordered_map<std::string, std::function<std::vector<char>(const std::string &)>> key_gens = {
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
		std::unique_ptr<encryptor> enc;
		std::unique_ptr<decryptor> dec;
	};

	template <typename BaseCrypto, size_t KeySize, size_t IvSize>
	Cryptor CryptoPPCryptoFactory()
	{
		return Cryptor{
			std::make_unique<encryptor_cryptopp<BaseCrypto, KeySize, IvSize>>(),
			std::make_unique<decryptor_cryptopp<BaseCrypto, KeySize, IvSize>>()
		};
	}

	template <typename BaseCrypto, size_t KeySize, size_t IvSize, size_t TagSize>
	Cryptor CryptoPPAuthCryptoFactory()
	{
		return Cryptor{
			std::make_unique<encryptor_cryptopp_auth<BaseCrypto, KeySize, IvSize, TagSize>>(),
			std::make_unique<decryptor_cryptopp_auth<BaseCrypto, KeySize, IvSize, TagSize>>()
		};
	}

	Cryptor CryptoFactory(const std::string &method)
	{
		static const std::unordered_map<std::string, std::function<Cryptor()>> factories = {
			{"none", []()->Cryptor { return Cryptor{ std::make_unique<encryptor_plain>(), std::make_unique<decryptor_plain>() }; }},
			{"aes-128-ctr", []()->Cryptor { return CryptoPPCryptoFactory<CTR_Mode<AES>, 128, 128>(); }},
			{"aes-256-ctr", []()->Cryptor { return CryptoPPCryptoFactory<CTR_Mode<AES>, 256, 128>(); }},
			{"aes-128-cfb", []()->Cryptor { return CryptoPPCryptoFactory<CFB_Mode<AES>, 128, 128>(); }},
			{"aes-256-cfb", []()->Cryptor { return CryptoPPCryptoFactory<CFB_Mode<AES>, 256, 128>(); }},
			{"aes-128-gcm", []()->Cryptor { return CryptoPPAuthCryptoFactory<GCM<AES>, 128, 96, 128>(); }},
			{"chacha20-poly1305", []()->Cryptor { return CryptoPPAuthCryptoFactory<ChaCha20Poly1305, 256, 96, 128>(); }},
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

	uint8_t HexDigit(char ch)
	{
		switch (ch)
		{
		case '0':
			return 0;
		case '1':
			return 1;
		case '2':
			return 2;
		case '3':
			return 3;
		case '4':
			return 4;
		case '5':
			return 5;
		case '6':
			return 6;
		case '7':
			return 7;
		case '8':
			return 8;
		case '9':
			return 9;
		case 'A':
		case 'a':
			return 10;
		case 'B':
		case 'b':
			return 11;
		case 'C':
		case 'c':
			return 12;
		case 'D':
		case 'd':
			return 13;
		case 'E':
		case 'e':
			return 14;
		case 'F':
		case 'f':
			return 15;
		default:
			assert(false);
			return -1;
		}
	}

}

void ObjectReferenceNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

RawTcpSocketNode::RawTcpSocketNode(asio::io_context &io_context)
	:io_context_(io_context)
{
}

void RawTcpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_tcp_socket> RawTcpSocketNode::NewTcpSocket()
{
	return std::make_unique<raw_tcp_socket>(io_context_);
}

HttpTcpSocketNode::HttpTcpSocketNode(ServerConfigurationNode *base, const endpoint &server_endpoint)
	:LayeredTcpSocketNode(base),
	server_endpoint_(server_endpoint)
{
}

void HttpTcpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_tcp_socket> HttpTcpSocketNode::NewTcpSocket()
{
	return std::make_unique<http_tcp_socket>(Base().NewTcpSocket(), server_endpoint_);
}

Socks5TcpSocketNode::Socks5TcpSocketNode(ServerConfigurationNode *base, const endpoint &server_endpoint)
	:LayeredTcpSocketNode(base),
	server_endpoint_(server_endpoint)
{
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

SSTcpSocketNode::SSTcpSocketNode(ServerConfigurationNode *base, const endpoint &server_endpoint)
	:LayeredTcpSocketNode(base),
	server_endpoint_(server_endpoint)
{
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
	return std::make_unique<ss::ss_crypto_tcp_socket>(Base().NewTcpSocket(), key_, std::move(cryptor.enc), std::move(cryptor.dec));
}

void SSCryptoTcpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_tcp_socket> SSCryptoTcpSocketNode::NewTcpSocket()
{
	return NewSSCryptoTcpSocket();
}

SSRAuthAes128Sha1TcpSocketNode::SSRAuthAes128Sha1TcpSocketNode(ServerConfigurationNode *base, const std::string &param)
	:LayeredNodeTemplate(base), param_(param)
{
}

void SSRAuthAes128Sha1TcpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_tcp_socket> SSRAuthAes128Sha1TcpSocketNode::NewTcpSocket()
{
	return std::make_unique<ssr::ssr_auth_aes128_sha1_tcp_socket>(Base().NewSSCryptoTcpSocket(), GetSSRAuthAes128Sha1SharedServerData(param_));
}

SSRHttpSimpleTcpSocketNode::SSRHttpSimpleTcpSocketNode(ServerConfigurationNode *base, const std::string &param)
	:LayeredTcpSocketNode(base), param_(param)
{
}

void SSRHttpSimpleTcpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_tcp_socket> SSRHttpSimpleTcpSocketNode::NewTcpSocket()
{
	return std::make_unique<ssr::ssr_http_simple_tcp_socket>(Base().NewTcpSocket(), param_);
}

VMessTcpSocketNode::VMessTcpSocketNode(ServerConfigurationNode *base, const endpoint &server_endpoint, const std::string &uid, const std::string &security)
	:LayeredNodeTemplate(base), server_endpoint_(server_endpoint), security_str_(security)
{
	size_t pos = 0;
	for (int i = 0; i < 16; ++i)
	{
		while (pos < uid.size() && !isxdigit(uid[pos]))
			++pos;
		if (pos >= uid.size())
			throw std::invalid_argument("Invalid uuid");
		char h = uid[pos++];
		while (pos < uid.size() && !isxdigit(uid[pos]))
			++pos;
		if (pos >= uid.size())
			throw std::invalid_argument("Invalid uuid");
		char l = uid[pos++];
		uid_[i] = HexDigit(h) << 4 | HexDigit(l);
	}
	if (security == "aes-128-gcm")
		security_ = v2ray::SEC_AES_128_GCM;
	else if (security == "chacha20-poly1305")
		security_ = v2ray::SEC_CHACHA20_POLY1305;
	else if (security == "none")
		security_ = v2ray::SEC_NONE;
	else
		throw std::invalid_argument("Invalid security");
}

void VMessTcpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_tcp_socket> VMessTcpSocketNode::NewTcpSocket()
{
	Cryptor cryptor = CryptoFactory(security_str_);
	return std::make_unique<v2ray::vmess_tcp_socket>(Base().NewTcpSocket(), server_endpoint_, uid_, security_, std::move(cryptor.enc), std::move(cryptor.dec));
}

WeightBasedSwitchTcpSocketNode::WeightBasedSwitchTcpSocketNode(Container &&base, Modes mode)
	:base_(std::move(base)), mode_(mode), itr_(base_.begin()), total_(0)
{
	if (base_.empty())
		throw std::invalid_argument("Need at least one base");
	for (const auto &p : base_)
	{
		if (p.weight < 0)
			throw std::invalid_argument("Weight must not be negative");
		total_ += p.weight;
	}
	if (total_ == 0)
		throw std::invalid_argument("Total weight must be more than 1");

	for (auto itr = base_.begin(), itr_end = base_.end(); itr != itr_end; ++itr)
		itr->acc = 0;
	itr_->acc = itr_->weight;
	while (itr_->acc < 1)
	{
		++itr_;
		if (itr_ == base_.end())
			itr_ = base_.begin();
		itr_->acc += itr_->weight;
	}
}

void WeightBasedSwitchTcpSocketNode::Validate() const
{
	for (const auto &p : base_)
		if (dynamic_cast<const TcpSocketNode *>(p.node) == nullptr)
			throw std::invalid_argument("Invalid base");
}

void WeightBasedSwitchTcpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_tcp_socket> WeightBasedSwitchTcpSocketNode::NewTcpSocket()
{
	switch (mode_)
	{
	case Modes::SEQUENTIAL:
	{
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		std::unique_ptr<prx_tcp_socket> socket = static_cast<TcpSocketNode *>(itr_->node)->NewTcpSocket();
		itr_->acc -= 1;
		while (itr_->acc < 1)
		{
			++itr_;
			if (itr_ == base_.end())
				itr_ = base_.begin();
			itr_->acc += itr_->weight;
		}
		return socket;
	}
	case Modes::RANDOM:
	{
		thread_local static std::default_random_engine generator(std::random_device{}());
		std::uniform_real_distribution<double> distribution(0, total_);
		double counter = distribution(generator);
		Iterator itr = base_.begin();
		while (counter >= itr->weight)
		{
			counter -= itr->weight;
			++itr;
			assert(itr_ != base_.end());
		}
		return static_cast<TcpSocketNode *>(itr->node)->NewTcpSocket();
	}
	default:
		assert(false);
		throw std::invalid_argument("Invalid mode");
	}
}

RawUdpSocketNode::RawUdpSocketNode(asio::io_context &io_context)
	:io_context_(io_context)
{
}

void RawUdpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_udp_socket> RawUdpSocketNode::NewUdpSocket()
{
	return std::make_unique<raw_udp_socket>(io_context_);
}

Socks5UdpSocketNode::Socks5UdpSocketNode(ServerConfigurationNode *base, const endpoint &server_endpoint)
	:base_(base), udp_base_(nullptr),
	server_endpoint_(server_endpoint)
{
}

Socks5UdpSocketNode::Socks5UdpSocketNode(ServerConfigurationNode *base, ServerConfigurationNode *udp_base, const endpoint &server_endpoint)
	:base_(base), udp_base_(udp_base),
	server_endpoint_(server_endpoint)
{
}

void Socks5UdpSocketNode::Validate() const
{
	if (dynamic_cast<const TcpSocketNode *>(base_) == nullptr)
		throw std::invalid_argument("Invalid base for base of Socks5UdpSocket");
	if (udp_base_ && dynamic_cast<const UdpSocketNode *>(udp_base_) == nullptr)
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

SSUdpSocketNode::SSUdpSocketNode(ServerConfigurationNode *base, const endpoint &server_endpoint)
	:LayeredUdpSocketNode(base),
	server_endpoint_(server_endpoint)
{
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
	return std::make_unique<ss::ss_crypto_udp_socket>(Base().NewUdpSocket(), key_, std::move(cryptor.enc), std::move(cryptor.dec));
}

void SSCryptoUdpSocketNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_udp_socket> SSCryptoUdpSocketNode::NewUdpSocket()
{
	return NewSSCryptoUdpSocket();
}

RawListenerNode::RawListenerNode(asio::io_context &io_context)
	:io_context_(io_context)
{
}

void RawListenerNode::AcceptVisitor(ServerConfigurationVisitor &visitor)
{
	visitor.Visit(*this);
}

std::unique_ptr<prx_listener> RawListenerNode::NewListener()
{
	return std::make_unique<raw_listener>(io_context_);
}

Socks5ListenerNode::Socks5ListenerNode(ServerConfigurationNode *base, const endpoint &server_endpoint)
	:LayeredNodeTemplate(base),
	server_endpoint_(server_endpoint)
{
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
	int parallel_accept,
	const endpoint &upstream_local_endpoint,
	ServerConfigurationNode *upstream_listener,
	ServerConfigurationNode *upstream_udp_socket,
	ServerConfigurationNode *downstream_tcp_socket,
	ServerConfigurationNode *downstream_udp_socket,
	ServerConfigurationNode *downstream_listener
)
	:thread_count_(thread_count), parallel_accept_(parallel_accept),
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
	if (dynamic_cast<const TcpSocketNode *>(downstream_tcp_socket_) == nullptr)
		throw std::invalid_argument("Invalid downstream tcp socket");
	if (dynamic_cast<const UdpSocketNode *>(upstream_udp_socket_) == nullptr)
		throw std::invalid_argument("Invalid upstream udp socket");
	if (dynamic_cast<const UdpSocketNode *>(downstream_udp_socket_) == nullptr)
		throw std::invalid_argument("Invalid downstream udp socket");
	if (dynamic_cast<const ListenerNode *>(upstream_listener_) == nullptr)
		throw std::invalid_argument("Invalid upstream listener");
	if (dynamic_cast<const ListenerNode *>(downstream_listener_) == nullptr)
		throw std::invalid_argument("Invalid downstream listener");
}
