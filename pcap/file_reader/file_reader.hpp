#ifndef PCAP_FILE_READER_HPP
#define PCAP_FILE_READER_HPP

#include <bit>
#include <cstdint>
#include <fstream>
#include <optional>
#include <string>

#include "byte_buffer/byte_buffer.hpp"

namespace pcap
{
class Packet;

class FileReader final
{
public:
	explicit FileReader(const std::string& fileName);

	/**
	 * @brief Returns file size.
	 * 
	 * @return File size
	 */
	[[nodiscard]] uint64_t fileSize() const noexcept;

	/**
	 * @brief Reads next PCAP packet from the file.
	 * 
	 * @param packet Packet
	 * 
	 * @return `False` if this is the end of the file, otherwise - `true`.
	 */
	[[nodiscard]] bool readNextPacket(Packet& packet);

	/**
	 * @brief Returns number of bytes read.
	 * 
	 * @return Number of bytes read
	 */
	[[nodiscard]] uint64_t readBytes() const noexcept;

	/**
	 * @brief Returns number of packets read.
	 * 
	 * @return Number of packets read 
	 */
	[[nodiscard]] uint64_t readPackets() const noexcept;

private:
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

	enum TimestampType : int8_t
	{
		NANOSECONDS,
		MICROSECONDS
	};

	[[nodiscard]] bool readFileHeader() noexcept;
	[[nodiscard]] std::optional<PacketHeader> readPacketHeader() noexcept;
	void clearResources();

	static bool validateFileHeader(const uint8_t* header, uint16_t size) noexcept;
	static void toNativeByteOrder(FileHeader& header, std::endian headerEndian) noexcept;
	static void toNativeByteOrder(PacketHeader& header, std::endian headerEndian) noexcept;
	static std::endian fileEndian(uint8_t byte) noexcept;
	static TimestampType fileTimestampType(uint8_t byte) noexcept;

	std::ifstream file_;
	std::endian filebyteOrder_;
	TimestampType fileTimestampType_;
	byte_buffer::ByteBuffer buffer_;
	uint32_t linkLayerType_;
	uint64_t fileSize_;
	uint64_t readBytes_;
	uint64_t readPackets_;
};
} // namespace pcap

#endif
