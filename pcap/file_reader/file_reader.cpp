#include <chrono>
#include <cstring>
#include <format>
#include <iostream>
#include <stdexcept>

#include "file_reader.hpp"
#include "pcap/packet/packet.hpp"
#include "pcap/utils/byte_swapper.hpp"

constexpr uint8_t magicNumberLittleEndianMicroseconds[]{0xd4, 0xc3, 0xb2, 0xa1};
constexpr uint8_t magicNumberLittleEndianNanoseconds[]{0x4d, 0x3c, 0xb2, 0xa1};
constexpr uint8_t magicNumberBigEndianMicroseconds[]{0xa1, 0xb2, 0xc3, 0xd4};
constexpr uint8_t magicNumberBigEndianNanoseconds[]{0xa1, 0xb2, 0x3c, 0x4d};

namespace pcap
{
FileReader::FileReader(const std::string& fileName)
	: file_(fileName, std::ios::binary)
	, fileEndian_{std::endian::native}
	, timestampType_{TimestampType::undefined}
	, buffer_{}
	, linkLayerType_{}
	, fileSize_{}
	, readBytes_{}
	, readPackets_{}
{
	if (not file_.is_open())
	{
		clear();
		throw std::runtime_error(std::format("pcap::FileReader [exception]: cannot open '{}': file does not exist.", fileName));
	}

	std::cout << std::format("pcap::FileReader [info]: file '{}' was successfully opened\n", fileName);

	file_.seekg(std::ios::beg, std::ios::end);
	fileSize_ = file_.tellg();
	file_.seekg(std::ios::beg, std::ios::beg);

	std::cout << std::format("pcap::FileReader [info]: file size {} bytes\n", fileSize_);

	if (not readFileHeader())
	{
		clear();
		throw std::runtime_error("pcap::FileReader [exception]: file header validation faile: this is not a PCAP file.");
	}
}

FileReader::FileReader(FileReader&& reader) noexcept
	: file_(std::move(reader.file_))
	, fileEndian_{std::endian::native}
	, timestampType_{TimestampType::undefined}
	, buffer_{std::move(reader.buffer_)}
	, linkLayerType_{}
	, fileSize_{}
	, readBytes_{}
	, readPackets_{}
{
	std::swap(fileEndian_, reader.fileEndian_);
	std::swap(timestampType_, reader.timestampType_);
	std::swap(linkLayerType_, reader.linkLayerType_);
	std::swap(fileSize_, reader.fileSize_);
	std::swap(readBytes_, reader.readBytes_);
	std::swap(readPackets_, reader.readPackets_);
}

FileReader& FileReader::operator=(FileReader&& reader) noexcept
{
	if (this != &reader)
	{
		clear();

		std::swap(file_, reader.file_);
		std::swap(fileEndian_, reader.fileEndian_);
		std::swap(timestampType_, reader.timestampType_);
		std::swap(buffer_, reader.buffer_);
		std::swap(linkLayerType_, reader.linkLayerType_);
		std::swap(fileSize_, reader.fileSize_);
		std::swap(readBytes_, reader.readBytes_);
		std::swap(readPackets_, reader.readPackets_);
	}

	return *this;
}

uint64_t FileReader::fileSize() const noexcept
{
	return fileSize_;
}

bool FileReader::readNextPacket(Packet& packet)
{
	if (readBytes_ == fileSize_)
	{
		return false;
	}

	const auto packetHeader{readPacketHeader()};

	if (not packetHeader)
	{
		clear();
		throw std::runtime_error("pcap::FileReader [exception]: cannot read PCAP packet header: file corrupted");
	}

	buffer_.fill(file_, packetHeader->currentLength, byte_buffer::FillingMode::truncate);

	readBytes_ += packetHeader->currentLength;
	++readPackets_;

	const auto packetTimestamp{
		std::chrono::seconds{packetHeader->timestampSec} + (timestampType_ == TimestampType::nanoseconds ?
									    std::chrono::nanoseconds{packetHeader->timestampMicrosec} :
									    std::chrono::microseconds{packetHeader->timestampMicrosec})};

	packet.fill(std::chrono::duration_cast<std::chrono::nanoseconds>(packetTimestamp), linkLayerType_, buffer_);

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
	uint8_t buffer[sizeof(FileHeader)]{};
	readBytes_ += file_.read(reinterpret_cast<char*>(buffer), sizeof(FileHeader)).gcount();

	if (not validateFileHeader({buffer, readBytes_}))
	{
		return false;
	}

	fileEndian_ = getFileEndian(buffer[0]);
	timestampType_ = getTimestampType(buffer[0]);

	FileHeader header{};
	std::memcpy(&header, buffer, sizeof(FileHeader));

	ByteSwapper{}(header, fileEndian_);

	linkLayerType_ = header.linkLayerType;
	buffer_.reserve(header.snapLength);

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

	ByteSwapper{}(header, fileEndian_);

	return header;
}

void FileReader::clear()
{
	file_.close();
	fileEndian_ = std::endian::native;
	timestampType_ = TimestampType::undefined;
	buffer_.destroy();
	linkLayerType_ = 0;
	fileSize_ = 0;
	readBytes_ = 0;
	readPackets_ = 0;
}

bool FileReader::validateFileHeader(std::span<const uint8_t> data) noexcept
{
	if ((sizeof(FileHeader) == data.size()) &&
	    (!std::memcmp(data.data(), magicNumberBigEndianMicroseconds, std::size(magicNumberBigEndianMicroseconds)) ||
	     !std::memcmp(data.data(), magicNumberBigEndianNanoseconds, std::size(magicNumberBigEndianNanoseconds)) ||
	     !std::memcmp(data.data(), magicNumberLittleEndianMicroseconds, std::size(magicNumberLittleEndianMicroseconds)) ||
	     !std::memcmp(data.data(), magicNumberLittleEndianNanoseconds, std::size(magicNumberLittleEndianNanoseconds))))
	{
		return true;
	}

	return false;
}

std::endian FileReader::getFileEndian(uint8_t byte) noexcept
{
	return (byte == magicNumberLittleEndianMicroseconds[0] || byte == magicNumberLittleEndianNanoseconds[0]) ? std::endian::little :
														   std::endian::big;
}

FileReader::TimestampType FileReader::getTimestampType(uint8_t byte) noexcept
{
	return (byte == magicNumberLittleEndianMicroseconds[0] || byte == magicNumberBigEndianMicroseconds[0]) ? TimestampType::microseconds :
														 TimestampType::nanoseconds;
}
} // namespace pcap
