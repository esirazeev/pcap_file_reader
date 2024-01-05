#include <chrono>
#include <cstring>
#include <format>
#include <iostream>
#include <stdexcept>

#include "file_reader.hpp"
#include "pcap/packet/packet.hpp"
#include "pcap/utils/bytes_swap.hpp"

namespace pcap
{
FileReader::FileReader(const std::string& fileName)
	: file_(fileName, std::ios::binary)
	, filebyteOrder_{std::endian::native}
	, fileTimestampType_{TimestampType::NANOSECONDS}
	, buffer_{}
	, fileSize_{}
	, readBytes_{}
	, readPackets_{}
	, linkLayerType_{}
{
	if (!file_.is_open())
	{
		clearResources();
		throw std::runtime_error(std::format("pcap::FileReader [exception]: cannot open '{}': file does not exist.", fileName));
	}

	std::cout << std::format("pcap::FileReader [info]: file '{}' was successfully opened\n", fileName);

	file_.seekg(std::ios::beg, std::ios::end);
	fileSize_ = file_.tellg();
	file_.seekg(std::ios::beg, std::ios::beg);

	std::cout << std::format("pcap::FileReader [info]: file size {} bytes\n", fileSize_);

	if (!readFileHeader())
	{
		clearResources();
		throw std::runtime_error("pcap::FileReader [exception]: file header validation faile: this is not a PCAP file.");
	}
}

uint64_t FileReader::fileSize() const noexcept
{
	return fileSize_;
}

bool FileReader::readNextPacket(Packet& packet)
{
	if (readBytes_ == fileSize_)
	{
		std::cout << std::format("pcap::FileReader [info]: file reading finished\n");
		std::cout << std::format("pcap::FileReader [info]: read bytes  : {}\n", readBytes_);
		std::cout << std::format("pcap::FileReader [info]: read packets: {}\n", readPackets_);

		return false;
	}

	const auto packetHeader{readPacketHeader()};

	if (!packetHeader)
	{
		clearResources();
		throw std::runtime_error("pcap::FileReader [exception]: cannot read PCAP packet header: file corrupted");
	}

	const auto packetTimestamp{
		std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::seconds{packetHeader->timestampSec}).count() +
		(fileTimestampType_ != TimestampType::NANOSECONDS ?
			 packetHeader->timestampMicrosec :
			 std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::microseconds{packetHeader->timestampMicrosec}).count())};

	buffer_.fill(file_, packetHeader->currentLength);
	readBytes_ += buffer_.size();
	++readPackets_;

	packet.fill(packetTimestamp, linkLayerType_, buffer_);

	return true;
}

uint64_t FileReader::readBytes() const noexcept
{
	return readBytes_;
}

uint64_t FileReader::readPackets() const noexcept
{
	return readPackets_;
}

bool FileReader::readFileHeader() noexcept
{
	uint8_t buffer[sizeof(FileHeader)] = {};
	readBytes_ += file_.read(reinterpret_cast<char*>(&buffer), sizeof(FileHeader)).gcount();

	if (!validateFileHeader(buffer, readBytes_))
	{
		return false;
	}

	filebyteOrder_ = fileEndian(buffer[0]);
	fileTimestampType_ = fileTimestampType(buffer[0]);

	FileHeader header{};
	std::memcpy(&header, buffer, sizeof(FileHeader));

	toNativeByteOrder(header, filebyteOrder_);

	linkLayerType_ = header.linkLayerType;
	buffer_.reallocate(header.snapLength);

	return true;
}

std::optional<FileReader::PacketHeader> FileReader::readPacketHeader() noexcept
{
	PacketHeader header{};
	const auto curReadBytes{file_.read(reinterpret_cast<char*>(&header), sizeof(PacketHeader)).gcount()};

	if (curReadBytes != sizeof(PacketHeader))
	{
		return std::nullopt;
	}

	readBytes_ += curReadBytes;

	toNativeByteOrder(header, filebyteOrder_);

	return header;
}

void FileReader::clearResources()
{
	buffer_.~ByteBuffer();
	file_.close();
}

bool FileReader::validateFileHeader(const uint8_t* header, uint16_t size) noexcept
{
	static constexpr uint8_t littleEndianMagicNumberMicroseconds[]{0xd4, 0xc3, 0xb2, 0xa1};
	static constexpr uint8_t littleEndianMagicNumberNanoseconds[]{0x4d, 0x3c, 0xb2, 0xa1};
	static constexpr uint8_t bigEndianMagicNumberMicroseconds[]{0xa1, 0xb2, 0xc3, 0xd4};
	static constexpr uint8_t bigEndianMagicNumberNanoseconds[]{0x34, 0xcd, 0xb2, 0xa1};

	if ((sizeof(FileHeader) == size) && (!std::memcmp(header, littleEndianMagicNumberMicroseconds, sizeof(uint32_t)) ||
					     !std::memcmp(header, littleEndianMagicNumberNanoseconds, sizeof(uint32_t)) ||
					     !std::memcmp(header, bigEndianMagicNumberMicroseconds, sizeof(uint32_t)) ||
					     !std::memcmp(header, bigEndianMagicNumberNanoseconds, sizeof(uint32_t))))
	{
		return true;
	}

	return false;
}

void FileReader::toNativeByteOrder(FileHeader& header, std::endian headerEndian) noexcept
{
	if (headerEndian != std::endian::native)
	{
		header.magicNumber = bswap32(header.magicNumber);
		header.versionMajor = bswap16(header.versionMajor);
		header.versionMinor = bswap16(header.versionMinor);
		header.snapLength = bswap32(header.snapLength);
		header.linkLayerType = bswap32(header.linkLayerType);
	}
}

void FileReader::toNativeByteOrder(PacketHeader& header, std::endian headerEndian) noexcept
{
	if (headerEndian != std::endian::native)
	{
		header.timestampSec = bswap32(header.timestampSec);
		header.timestampMicrosec = bswap32(header.timestampMicrosec);
		header.currentLength = bswap32(header.currentLength);
		header.orignalLength = bswap32(header.orignalLength);
	}
}

std::endian FileReader::fileEndian(uint8_t byte) noexcept
{
	return (byte == 0xd4 || byte == 0x4d) ? std::endian::little : std::endian::big;
}

FileReader::TimestampType FileReader::fileTimestampType(uint8_t byte) noexcept
{
	return (byte == 0x4d || byte == 0x34) ? TimestampType::MICROSECONDS : TimestampType::NANOSECONDS;
}
} // namespace pcap
