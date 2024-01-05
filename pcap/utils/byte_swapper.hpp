#ifndef PCAP_UTILS_BYTE_SWAPPER_HPP
#define PCAP_UTILS_BYTE_SWAPPER_HPP

#ifdef __WIN32
#include <winsock2.h>
#define bswap16(value) __builtin_bswap16(value)
#define bswap32(value) __builtin_bswap32(value)
#define bswap64(value) __builtin_bswap64(value)
#elif __linux__
#include <byteswap.h>
#define bswap16(value) bswap_16(value)
#define bswap32(value) bswap_32(value)
#define bswap64(value) bswap_64(value)
#endif

#include <bit>

#include "pcap/file_reader/file_reader.hpp"
#include "pcap/network_layer/network_layers.hpp"

namespace pcap
{
struct ByteSwapper final
{
	void operator()(FileReader::FileHeader& header, std::endian endian) const noexcept
	{
		if (endian != std::endian::native)
		{
			header.magicNumber = bswap32(header.magicNumber);
			header.versionMajor = bswap16(header.versionMajor);
			header.versionMinor = bswap16(header.versionMinor);
			header.snapLength = bswap32(header.snapLength);
			header.linkLayerType = bswap32(header.linkLayerType);
		}
	}

	void operator()(FileReader::PacketHeader& header, std::endian endian) const noexcept
	{
		if (endian != std::endian::native)
		{
			header.timestampSec = bswap32(header.timestampSec);
			header.timestampMicrosec = bswap32(header.timestampMicrosec);
			header.currentLength = bswap32(header.currentLength);
			header.orignalLength = bswap32(header.orignalLength);
		}
	}

	void operator()(network_layer::Ethernet& ethernet) const noexcept
	{
		if constexpr (std::endian::native != std::endian::little)
		{
			// TODO
			// swap destination
			// swap source
			ethernet.type = bswap16(ethernet.type);
		}
	}

	void operator()(network_layer::IPv4& ipv4) const noexcept
	{
		if constexpr (std::endian::native != std::endian::little)
		{
			ipv4.totalLength = bswap16(ipv4.totalLength);
			ipv4.identification = bswap16(ipv4.identification);
			ipv4.flagsOffset = bswap16(ipv4.flagsOffset);
			ipv4.checksum = bswap16(ipv4.checksum);
			ipv4.sourceAddress = bswap32(ipv4.sourceAddress);
			ipv4.destinationAddress = bswap32(ipv4.destinationAddress);
		}
	}

	void operator()(network_layer::Udp& udp) const noexcept
	{
		if constexpr (std::endian::native != std::endian::little)
		{
			udp.sourcePort = bswap16(udp.sourcePort);
			udp.destinationPort = bswap16(udp.destinationPort);
			udp.length = bswap16(udp.length);
			udp.checksum = bswap16(udp.checksum);
		}
	}
};
} // namespace pcap

#endif // PCAP_UTILS_BYTE_SWAPPER_HPP
