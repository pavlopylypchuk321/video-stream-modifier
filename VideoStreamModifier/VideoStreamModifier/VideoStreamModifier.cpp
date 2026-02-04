#include <cstdio>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
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
static void dumpUmpMetadata(PFStream* pContent)
{
    if (!pContent || pContent->size() == 0)
        return;

    std::vector<uint8_t> body(static_cast<size_t>(pContent->size()));
    pContent->seek(0, FILE_BEGIN);
    if (pContent->read(body.data(), static_cast<tStreamSize>(body.size())) != static_cast<tStreamSize>(body.size()))
        return;
    pContent->seek(0, FILE_BEGIN);

    CompositeBuffer::Chunk chunk(body.begin(), body.end());
    CompositeBuffer buffer({ chunk });
    UmpReader reader(std::move(buffer));
    reader.read([](int partNo, int type, int size) {
        printf("UMP part_no=%d type=%d size=%d\n", partNo, type, size);
    });
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
                    dumpUmpMetadata(object->getStream(HS_CONTENT));
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

    printf("UMP MITM: will print part_no, type, size for YouTube UMP streams.\n");
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
