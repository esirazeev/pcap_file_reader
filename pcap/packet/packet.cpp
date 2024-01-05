#include <cstring>
#include <format>
#include <iostream>

#include "packet.hpp"
#include "pcap/network_layer/error.hpp"

namespace pcap
{
Packet::Packet() noexcept : buffer_{}, linkLayerType_{}, timestampNanoSec_{} {}

Packet::Packet(Packet&& packet) noexcept
	: buffer_{std::move(packet.buffer_)}
	, layers_{std::move(packet.layers_)}
	, linkLayerType_{packet.linkLayerType_}
	, timestampNanoSec_{packet.timestampNanoSec_}
	, payload_{packet.payload_}
{
	packet.linkLayerType_ = 0;
	packet.timestampNanoSec_ = 0;
	packet.payload_ = {};
}

Packet& Packet::operator=(Packet&& packet) noexcept
{
	if (this != &packet)
	{
		buffer_ = std::move(packet.buffer_);
		layers_ = std::move(packet.layers_);

		linkLayerType_ = packet.linkLayerType_;
		packet.linkLayerType_ = 0;

		timestampNanoSec_ = packet.timestampNanoSec_;
		packet.timestampNanoSec_ = 0;

		payload_ = packet.payload_;
		packet.payload_ = {};
	}

	return *this;
}

void Packet::fill(uint64_t timestampNanoSec, uint32_t linkLayerType, const byte_buffer::ByteBuffer& buffer)
{
	timestampNanoSec_ = timestampNanoSec;
	linkLayerType_ = linkLayerType;
	buffer_ = buffer;
}

void Packet::fill(uint64_t timestampNanoSec, uint32_t linkLayerType, byte_buffer::ByteBuffer&& buffer)
{
	timestampNanoSec_ = timestampNanoSec;
	linkLayerType_ = linkLayerType;
	buffer_ = std::move(buffer);
}

uint64_t Packet::timestamp() const noexcept
{
	return timestampNanoSec_;
}

uint16_t Packet::size() const noexcept
{
	return buffer_.size();
}

bool Packet::parse() noexcept
{
	layers_.clear();
	payload_ = buffer_.data();

	uint32_t type{linkLayerType_};

	try
	{
		do
		{
			auto layer{getNetworkLayer(type)};

			if (!layer)
			{
				std::cerr << std::format("pcap::Packet: unsupported network layer {}", type);
				return false;
			}

			deserializeNetworkLayer(payload_, *layer);
			const auto [nextType, headerSize] = retriveNetworkLayerInfo(*layer);

			type = nextType;
			payload_ = payload_.subspan(headerSize, payload_.size() - headerSize);

			layers_.push_back(*layer);
		} while (type != static_cast<uint16_t>(NetworkLayerType::unsupported));

		return true;
	}
	catch (const NetworkLayerError& e)
	{
		std::cerr << std::format("pcap::Packet: {}: file corrupted\n", e.error());
		return false;
	}
}

const NetworkLayer_t* Packet::firstLayer() const noexcept
{
	return layers_.empty() ? nullptr : &layers_.front();
}

const NetworkLayer_t* Packet::lastLayer() const noexcept
{
	return layers_.empty() ? nullptr : &layers_.back();
}

const std::vector<NetworkLayer_t>& Packet::layers() const noexcept
{
	return layers_;
}

std::span<const uint8_t> Packet::payload() const noexcept
{
	return payload_;
}
} // namespace pcap
