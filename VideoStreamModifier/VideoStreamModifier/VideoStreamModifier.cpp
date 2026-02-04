#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#include "ProtocolFilters.h"
#include "PFEventsDefault.h"
#include "PFFilterDefs.h"
#include "samples_config.h"

#include "googlevideo_min/CompositeBuffer.h"
#include "googlevideo_min/UmpReader.h"

#ifdef _DEBUG
#include <crtdbg.h>
#endif

#pragma comment(lib, "ws2_32.lib")

using namespace ProtocolFilters;
using namespace GoogleVideoMin;
using namespace nfapi;

/** Segment numbers already written (0 = init, 1+ = media). Dedupe like SabrStream.downloadedSegments. */
static std::set<int> g_writtenSegmentNumbers;
/** When MediaHeader has no sequence_number, assign next index so we don't collapse all to segment 0. */
static int g_nextMediaSegmentIndex = 1;
static const char* g_segmentFilePrefix = "segment_";
static const char* g_segmentFileSuffix = ".mp4";

namespace
{
    constexpr int UMP_MEDIA_HEADER = 20;
    constexpr int UMP_MEDIA = 21;
    constexpr int UMP_MEDIA_END = 22;

    struct SegmentInfo
    {
        std::vector<uint8_t> data;
        int segmentNumber = -1;       /* 0 = init, 1+ = media (from MediaHeader.sequence_number) */
        int64_t contentLength = -1;   /* expected bytes, -1 = unknown */
    };

    /* Read protobuf varint from payload at offset; return (value, newOffset) or (-1, offset) if invalid. */
    static std::pair<int64_t, size_t> readVarint(const std::vector<uint8_t>& payload, size_t offset)
    {
        if (offset >= payload.size())
            return { -1, offset };
        int64_t value = 0;
        int shift = 0;
        for (; offset < payload.size() && shift < 64; offset++, shift += 7)
        {
            uint8_t b = payload[offset];
            value |= static_cast<int64_t>(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                return { value, offset + 1 };
        }
        return { -1, offset };
    }

    /* Parse MediaHeader protobuf: header_id(1), is_init_seg(8), sequence_number(9), content_length(14). */
    static bool parseMediaHeader(const std::vector<uint8_t>& payload, uint8_t& headerId, int& segmentNumber, int64_t& contentLength)
    {
        headerId = 0;
        segmentNumber = -1;  /* -1 = not set; use running index for media if missing */
        contentLength = -1;
        bool isInitSeg = false;
        bool hasSequenceNumber = false;

        size_t i = 0;
        while (i < payload.size())
        {
            int64_t tag;
            std::tie(tag, i) = readVarint(payload, i);
            if (tag < 0 || i > payload.size())
                break;
            int fieldNum = static_cast<int>(tag >> 3);
            int wireType = static_cast<int>(tag & 7);
            if (wireType != 0) /* varint */
                break;

            int64_t v;
            std::tie(v, i) = readVarint(payload, i);
            if (v < 0)
                break;

            if (fieldNum == 1)
                headerId = static_cast<uint8_t>(v);
            else if (fieldNum == 8)
                isInitSeg = (v != 0);
            else if (fieldNum == 9)
            {
                segmentNumber = static_cast<int>(v);
                hasSequenceNumber = true;
            }
            else if (fieldNum == 14)
                contentLength = v;
        }

        if (isInitSeg)
            segmentNumber = 0;
        else if (!hasSequenceNumber)
            segmentNumber = -1;  /* caller will assign g_nextMediaSegmentIndex */
        return true;
    }

    static bool writeSegmentToFile(int segmentNumber, const uint8_t* data, size_t size)
    {
        char path[256];
        sprintf_s(path, "%s%d%s", g_segmentFilePrefix, segmentNumber, g_segmentFileSuffix);
        FILE* f = nullptr;
        if (fopen_s(&f, path, "wb") != 0 || !f)
            return false;
        bool ok = (fwrite(data, 1, size, f) == size);
        fclose(f);
        if (ok)
            printf("Saved %s (%zu bytes)\n", path, size);
        return ok;
    }

    static void saveUmpToMp4(PFStream* pContent)
    {
        if (!pContent || pContent->size() == 0)
            return;

        std::vector<uint8_t> body(static_cast<size_t>(pContent->size()));
        pContent->seek(0, FILE_BEGIN);
        if (pContent->read(body.data(), static_cast<tStreamSize>(body.size())) != static_cast<tStreamSize>(body.size()))
            return;
        pContent->seek(0, FILE_BEGIN);

        std::map<uint8_t, SegmentInfo> segmentBuffers;

        CompositeBuffer::Chunk chunk(body.begin(), body.end());
        CompositeBuffer buffer({ chunk });
        UmpReader reader(std::move(buffer));

        reader.readWithData([&segmentBuffers](int partNo, int type, int size, const std::vector<uint8_t>& payload) {
            printf("UMP part_no=%d type=%d size=%d\n", partNo, type, size);

            
        });
    }
}


class UmpMitmFilter : public PFEventsDefault
{
public:
    virtual void tcpConnected(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
    {
        if (pConnInfo->direction == NF_D_OUT)
        {
            pf_addFilter(id, FT_PROXY);
            pf_addFilter(id, FT_SSL);
            pf_addFilter(id, FT_HTTP, FF_READ_ONLY_OUT | FF_READ_ONLY_IN | FF_HTTP_FILTER_WEBSOCKET | FF_HTTP_BLOCK_SPDY | FF_HTTP_IGNORE_RESPONSE_ERRORS);
            pf_addFilter(id, FT_HTTP2, FF_READ_ONLY_OUT | FF_READ_ONLY_IN);
        }
    }

    virtual void dataAvailable(ENDPOINT_ID id, PFObject* object)
    {
        if (object->getType() == OT_HTTP_RESPONSE || object->getType() == OT_HTTP2_RESPONSE)
        {
            PFHeader h;
            if (pf_readHeader(object->getStream(HS_HEADER), &h))
            {
                const PFHeaderField* pField = h.findFirstField("Content-Type");
                if (pField && pField->value().find("application/vnd.yt-ump") != std::string::npos)
                {
                    saveUmpToMp4(object->getStream(HS_CONTENT));
                }
            }
        }

        pf_postObject(id, object);
    }
};

int main(int argc, char* argv[])
{
    NF_RULE rule = {};
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return -1;

#ifdef _DEBUG
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_DEBUG);
#endif

    nf_adjustProcessPriviledges();

    printf("UMP MITM: printing UMP metadata and saving each segment to %s0%s, %s1%s, ...\n",
        g_segmentFilePrefix, g_segmentFileSuffix, g_segmentFilePrefix, g_segmentFileSuffix);
    printf("Press any key to stop...\n\n");

    UmpMitmFilter f;

    if (!pf_init(&f, L"c:\\netfilter2"))
    {
        printf("Failed to initialize protocol filter\n");
        WSACleanup();
        return -1;
    }

    pf_setRootSSLCertSubject("NFSDK Sample CA");

    if (nf_init(NFDRIVER_NAME, pf_getNFEventHandler()) != NF_STATUS_SUCCESS)
    {
        printf("Failed to connect to driver\n");
        pf_free();
        WSACleanup();
        return -1;
    }

    rule.protocol = IPPROTO_TCP;
    rule.filteringFlag = NF_FILTER;
    nf_addRule(&rule, TRUE);

    rule.protocol = IPPROTO_UDP;
    rule.remotePort = ntohs(80);
    rule.filteringFlag = NF_BLOCK;
    nf_addRule(&rule, TRUE);

    rule.protocol = IPPROTO_UDP;
    rule.remotePort = ntohs(443);
    rule.filteringFlag = NF_BLOCK;
    nf_addRule(&rule, TRUE);

    getchar();

    nf_free();
    pf_free();
    WSACleanup();

    return 0;
}
