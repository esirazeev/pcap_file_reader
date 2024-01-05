#ifndef NETWORK_LAYER_DESERIALIZE_HPP
#define NETWORK_LAYER_DESERIALIZE_HPP

#include <cstring>
#include <span>

#include "pcap/network_layer/error.hpp"
#include "pcap/network_layer/layer.hpp"
#include "pcap/utils/bytes_swap.hpp"

namespace pcap
{
class NetworLayerDeserializer final
{
public:
	void operator()(std::span<const uint8_t> data, Ethernet& header) const
	{
		if (!deserialize<Ethernet>(header, data))
		{
			throw NetworkLayerError(NetworkLayerType::ethernet, "cannot deserialize Ethernet header");
		}

		if constexpr (std::endian::native != std::endian::little)
		{
			// TODO
			// swap destination
			// swap source
			header.type = bswap16(header.type);
		}
	}

	void operator()(std::span<const uint8_t> data, IPv4& header) const
	{
		if (!deserialize<IPv4>(header, data))
		{
			throw NetworkLayerError(NetworkLayerType::ip_v4, "cannot deserialize IPv4 header");
		}

		if constexpr (std::endian::native != std::endian::little)
		{
			header.totalLength = bswap16(header.totalLength);
			header.identification = bswap16(header.identification);
			header.flagsOffset = bswap16(header.flagsOffset);
			header.checksum = bswap16(header.checksum);
			header.sourceAddress = bswap32(header.sourceAddress);
			header.destinationAddress = bswap32(header.destinationAddress);
		}
	}

	void operator()(std::span<const uint8_t> data, Udp& header) const
	{
		if (!deserialize<Udp>(header, data))
		{
			throw NetworkLayerError(NetworkLayerType::udp, "cannot deserialize Udp header");
		}

		if constexpr (std::endian::native != std::endian::little)
		{
			header.sourcePort = bswap16(header.sourcePort);
			header.destinationPort = bswap16(header.destinationPort);
			header.length = bswap16(header.length);
			header.checksum = bswap16(header.checksum);
		}
	}

private:
	template <typename T>
	[[nodiscard]] static bool deserialize(T& header, std::span<const uint8_t> data) noexcept
	{
		if (data.size() < sizeof(T)) [[unlikely]]
		{
			return false;
		}

		std::memcpy(&header, data.data(), sizeof(T));

		return true;
	}
};
} // namespace pcap

#endif // NETWORK_LAYER_DESERIALIZE_HPP
