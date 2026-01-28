
#include "CompositeBuffer.h"

#include <stdexcept>

using namespace GoogleVideoMin;

CompositeBuffer::CompositeBuffer()
    : chunks(), currentChunkOffset(0), currentChunkIndex(0), totalLength_(0)
{
}

CompositeBuffer::CompositeBuffer(const std::vector<Chunk> &chunksInit)
    : chunks(), currentChunkOffset(0), currentChunkIndex(0), totalLength_(0)
{
    for (const auto &c : chunksInit)
        append(c);
}

void CompositeBuffer::append(const Chunk &chunk)
{
    if (chunk.empty())
        return;

    if (canMergeWithLastChunk(chunk))
    {
        Chunk &last = chunks.back();
        last.insert(last.end(), chunk.begin(), chunk.end());
        resetFocus();
    }
    else
    {
        chunks.push_back(chunk);
    }
    totalLength_ += chunk.size();
}

void CompositeBuffer::append(const CompositeBuffer &other)
{
    for (const auto &c : other.chunks)
        append(c);
}

std::pair<CompositeBuffer, CompositeBuffer> CompositeBuffer::split(size_t position) const
{
    CompositeBuffer extracted;
    CompositeBuffer remaining;

    size_t pos = position;
    for (const auto &chunk : chunks)
    {
        if (pos >= chunk.size())
        {
            extracted.append(chunk);
            pos -= chunk.size();
        }
        else if (pos > 0)
        {
            Chunk first(chunk.begin(), chunk.begin() + pos);
            Chunk second(chunk.begin() + pos, chunk.end());
            extracted.append(first);
            remaining.append(second);
            pos = 0;
        }
        else
        {
            remaining.append(chunk);
        }
    }

    return {extracted, remaining};
}

size_t CompositeBuffer::getLength() const { return totalLength_; }

bool CompositeBuffer::canReadBytes(size_t position, size_t length) const
{
    return position + length <= totalLength_;
}

uint8_t CompositeBuffer::getUint8(size_t position) const
{
    focus(position);
    if (chunks.empty())
        throw std::out_of_range("CompositeBuffer is empty");
    const auto &chunk = chunks[currentChunkIndex];
    size_t idx = position - currentChunkOffset;
    if (idx >= chunk.size())
        throw std::out_of_range("Position outside focused chunk");
    return chunk[idx];
}

void CompositeBuffer::focus(size_t position) const
{
    if (chunks.empty())
        return;
    if (!isFocused(position))
    {
        if (position < currentChunkOffset)
            resetFocus();

        while (currentChunkIndex < chunks.size() - 1 &&
               currentChunkOffset + chunks[currentChunkIndex].size() <= position)
        {
            currentChunkOffset += chunks[currentChunkIndex].size();
            currentChunkIndex += 1;
        }
    }
}

bool CompositeBuffer::isFocused(size_t position) const
{
    if (chunks.empty())
        return false;
    return position >= currentChunkOffset &&
           position < currentChunkOffset + chunks[currentChunkIndex].size();
}

void CompositeBuffer::resetFocus() const
{
    currentChunkIndex = 0;
    currentChunkOffset = 0;
}

bool CompositeBuffer::canMergeWithLastChunk(const Chunk & /*chunk*/) const
{
    // Conservative behavior: avoid merging.
    return false;
}


