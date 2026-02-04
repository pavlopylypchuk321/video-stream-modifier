#include "UmpReader.h"

using namespace GoogleVideoMin;

UmpReader::UmpReader(CompositeBuffer buffer)
    : compositeBuffer(std::move(buffer))
{
}

void UmpReader::read(const std::function<void(int partNo, int type, int size)>& handlePart)
{
    static int partNo = 0;

    while (true)
    {
        int offset = 0;

        auto [partType, newOffset] = readVarInt(offset);
        offset = newOffset;

        auto [partSize, finalOffset] = readVarInt(offset);
        offset = finalOffset;

        if (partType < 0 || partSize < 0)
            break;

        if (!compositeBuffer.canReadBytes(offset, static_cast<size_t>(partSize)))
            break;

        handlePart(++partNo, partType, partSize);

        auto splitResult = compositeBuffer.split(offset);
        auto secondSplit = splitResult.second.split(partSize);
        compositeBuffer = secondSplit.second;
    }
}

void UmpReader::readWithData(const std::function<void(int partNo, int type, int size, const std::vector<uint8_t>& payload)>& handlePart)
{
    static int partNo = 0;

    while (true)
    {
        int offset = 0;

        auto [partType, newOffset] = readVarInt(offset);
        offset = newOffset;

        auto [partSize, finalOffset] = readVarInt(offset);
        offset = finalOffset;

        if (partType < 0 || partSize < 0)
            break;

        if (!compositeBuffer.canReadBytes(offset, static_cast<size_t>(partSize)))
            break;

        auto splitResult = compositeBuffer.split(offset);
        auto secondSplit = splitResult.second.split(partSize);
        std::vector<uint8_t> payload = secondSplit.first.toBytes();

        handlePart(++partNo, partType, partSize, payload);

        compositeBuffer = secondSplit.second;
    }
}

std::pair<int, int> UmpReader::readVarInt(int offset) const
{
    int byteLength = 0;

    if (compositeBuffer.canReadBytes(offset, 1))
    {
        uint8_t firstByte = compositeBuffer.getUint8(offset);
        if (firstByte < 128)
            byteLength = 1;
        else if (firstByte < 192)
            byteLength = 2;
        else if (firstByte < 224)
            byteLength = 3;
        else if (firstByte < 240)
            byteLength = 4;
        else
            byteLength = 5;
    }

    if (byteLength < 1 || !compositeBuffer.canReadBytes(offset, static_cast<size_t>(byteLength)))
        return {-1, offset};

    int value = 0;
    switch (byteLength)
    {
    case 1:
        value = compositeBuffer.getUint8(offset++);
        break;
    case 2:
    {
        int byte1 = compositeBuffer.getUint8(offset++);
        int byte2 = compositeBuffer.getUint8(offset++);
        value = (byte1 & 0x3f) + 64 * byte2;
        break;
    }
    case 3:
    {
        int byte1 = compositeBuffer.getUint8(offset++);
        int byte2 = compositeBuffer.getUint8(offset++);
        int byte3 = compositeBuffer.getUint8(offset++);
        value = (byte1 & 0x1f) + 32 * (byte2 + 256 * byte3);
        break;
    }
    case 4:
    {
        int byte1 = compositeBuffer.getUint8(offset++);
        int byte2 = compositeBuffer.getUint8(offset++);
        int byte3 = compositeBuffer.getUint8(offset++);
        int byte4 = compositeBuffer.getUint8(offset++);
        value = (byte1 & 0x0f) + 16 * (byte2 + 256 * (byte3 + 256 * byte4));
        break;
    }
    default:
    {
        int tempOffset = offset + 1;
        compositeBuffer.focus(tempOffset);
        int b0 = compositeBuffer.getUint8(tempOffset);
        int b1 = compositeBuffer.getUint8(tempOffset + 1);
        int b2 = compositeBuffer.getUint8(tempOffset + 2);
        int b3 = compositeBuffer.getUint8(tempOffset + 3);
        value = b0 + 256 * (b1 + 256 * (b2 + 256 * b3));
        offset += 5;
        break;
    }
    }

    return {value, offset};
}
