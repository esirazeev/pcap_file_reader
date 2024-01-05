#ifndef PCAP_FILE_READER_HPP
#define PCAP_FILE_READER_HPP

#include <bit>
#include <fstream>
#include <optional>
#include <span>
#include <string>

#include "byte_buffer/byte_buffer.hpp"

namespace pcap
{
class Packet;

class FileReader final
{
public:
#pragma pack(push, 1)
	struct FileHeader
	{
		uint32_t magicNumber;
		uint16_t versionMajor;
		uint16_t versionMinor;
		uint32_t timeZone;
		uint32_t timestampAccuracy;
		uint32_t snapLength;
		uint32_t linkLayerType;
	};

	struct PacketHeader
	{
		uint32_t timestampSec;
		uint32_t timestampMicrosec;
		uint32_t currentLength;
		uint32_t orignalLength;
	};
#pragma pack(pop)

	explicit FileReader(const std::string& fileName);
	FileReader(const FileReader&) = delete;
	FileReader(FileReader&&) noexcept;
	FileReader& operator=(const FileReader&) = delete;
	FileReader& operator=(FileReader&&) noexcept;

	/**
	 * @brief Returns the file size.
	 * 
	 * @return File size
	 */
	[[nodiscard]] uint64_t fileSize() const noexcept;

	/**
	 * @brief Reads the next packer from the file.
	 * 
	 * @param packet Packet
	 * 
	 * @return `True` if it hasn't reached the end of the file, otherwise - `false`
	 */
	[[nodiscard]] bool readNextPacket(Packet& packet);

	/**
	 * @brief Returns the number of bytes read.
	 * 
	 * @return Number of bytes read
	 */
	[[nodiscard]] uint64_t readBytes() const noexcept;

	/**
	 * @brief Returns the number of packets read.
	 * 
	 * @return Number of packets read 
	 */
	[[nodiscard]] uint64_t readPackets() const noexcept;

private:
	enum TimestampType : int8_t
	{
		undefined,
		nanoseconds,
		microseconds
	};

	bool readFileHeader() noexcept;
	std::optional<PacketHeader> readPacketHeader() noexcept;
	void clear();
	
	static bool validateFileHeader(std::span<const uint8_t> data) noexcept;
	static std::endian getFileEndian(uint8_t byte) noexcept;
	static TimestampType getTimestampType(uint8_t byte) noexcept;

	std::ifstream file_;
	std::endian fileEndian_;
	TimestampType timestampType_;
	byte_buffer::ByteBuffer buffer_;
	uint32_t linkLayerType_;
	uint64_t fileSize_;
	uint64_t readBytes_;
	uint64_t readPackets_;
};
} // namespace pcap

#endif
