// Blocks HTTP content by URL and text body.
//

#include "stdafx.h"
#include <crtdbg.h>
#include "ProtocolFilters.h"
#include "PFEventsDefault.h"

#include "samples_config.h"

#pragma comment(lib,"ws2_32.lib")

using namespace nfapi;
using namespace ProtocolFilters;

std::string g_urlString;
std::string g_newUrlString;

class HttpFilter : public PFEventsDefault
{
public:
	HttpFilter()
	{
	}

	virtual void tcpConnected(nfapi::ENDPOINT_ID id, nfapi::PNF_TCP_CONN_INFO pConnInfo)
	{
		pf_addFilter(id, FT_PROXY, FF_READ_ONLY_IN | FF_READ_ONLY_OUT);
		pf_addFilter(id, FT_SSL, FF_SSL_VERIFY | FF_SSL_TLS_AUTO); 
		pf_addFilter(id, FT_HTTP, FF_DONT_FILTER_IN | FF_HTTP_BLOCK_SPDY);
		pf_addFilter(id, FT_HTTP2, FF_DONT_FILTER_IN | FF_HTTP_BLOCK_SPDY);
	}

	std::string getHttpUrl(PFObject * object)
	{
		PFHeader h;
		PFStream * pStream;
		std::string url;
		std::string status;
		char * p;

		if (object->getType() == OT_HTTP_REQUEST)
		{
			if (pf_readHeader(object->getStream(HS_HEADER), &h))
			{
				PFHeaderField * pField = h.findFirstField("Host");
				if (pField)
				{
					url = "http://" + pField->value();
				}
			}

			pStream = object->getStream(HS_STATUS);
			if (!pStream)
				return "";

			status.resize((unsigned int)pStream->size());
			pStream->read((char*)status.c_str(), (tStreamSize)status.length());
			
			if (p = strchr((char*)status.c_str(), ' '))
			{
				p++;
				char * pEnd = strchr(p, ' ');
				if (pEnd)
				{
					if (strncmp(p, "http://", 7) == 0)
					{
						url = "";
					}
					url.append(p, pEnd-p+1);
				}
			}
		} else
		if (object->getType() == OT_HTTP2_REQUEST)
		{
			if (pf_readHeader(object->getStream(H2S_HEADER), &h))
			{
				PFHeaderField * pField = h.findFirstField(":authority");
				if (pField)
				{
					url = "http://" + pField->value();
				}

				pField = h.findFirstField(":path");
				if (pField)
				{
					url += pField->value();
				}
			}
		} else
		{
			return "";
		}
		
		return url;
	}

	void postRedirectHttpResponse(nfapi::ENDPOINT_ID id)
	{
		PFObject * newObj = PFObject_create(OT_HTTP_RESPONSE, 3);
		if (!newObj)
			return;

		const char status[] = "HTTP/1.1 302 Found\r\n";

		PFStream * pStream;
		
		pStream = newObj->getStream(HS_STATUS);
		if (pStream)
		{
			pStream->write(status, sizeof(status)-1);
		}

		pStream = newObj->getStream(HS_HEADER);
		if (pStream)
		{
			PFHeader h;

			h.addField("Location", g_newUrlString, true);
			h.addField("Content-Length", "0", true);
			h.addField("Connection", "close", true);
			pf_writeHeader(pStream, &h);
		}

		pf_postObject(id, newObj);

		newObj->free();
	}

	void postRedirectHttp2Response(nfapi::ENDPOINT_ID id, PFObject * requestObject)
	{
		PFObject * newObj = PFObject_create(OT_HTTP2_RESPONSE, 3);
		if (!newObj)
			return;

		PFStream * pStream;
		
		pStream = newObj->getStream(H2S_INFO);
		if (pStream)
		{
			requestObject->getStream(H2S_INFO)->copyTo(pStream);
		}

		pStream = newObj->getStream(H2S_HEADER);
		if (pStream)
		{
			PFHeader h;

			h.addField(":status", "302");
			h.addField("location", g_newUrlString);
			h.addField("content-length", "0");
			h.addField("connection", "close");

			pf_writeHeader(pStream, &h);
		}

		pf_postObject(id, newObj);

		newObj->free();
	}

	void dataAvailable(nfapi::ENDPOINT_ID id, PFObject * object)
	{
		if (object->getType() == OT_HTTP_REQUEST)
		{
			std::string url = strToLower(getHttpUrl(object));

			if (url.find(g_urlString) != std::string::npos)
			{
				postRedirectHttpResponse(id);
				return;
			}
		} else
		if (object->getType() == OT_HTTP2_REQUEST)
		{
			std::string url = strToLower(getHttpUrl(object));

			if (url.find(g_urlString) != std::string::npos)
			{
				postRedirectHttp2Response(id, object);
				return;
			}
		} 

		pf_postObject(id, object);
	}

	PF_DATA_PART_CHECK_RESULT 
	dataPartAvailable(nfapi::ENDPOINT_ID id, PFObject * object)
	{
		if (object->getType() == OT_HTTP_REQUEST)
		{
			std::string url = strToLower(getHttpUrl(object));

			if (url.find(g_urlString) != std::string::npos)
			{
				postRedirectHttpResponse(id);
				return DPCR_BLOCK;
			}
		} else
		if (object->getType() == OT_HTTP2_REQUEST)
		{
			std::string url = strToLower(getHttpUrl(object));

			if (url.find(g_urlString) != std::string::npos)
			{
				postRedirectHttp2Response(id, object);
				return DPCR_BLOCK;
			}
		}

		return DPCR_BYPASS;
	}

};

int main(int argc, char* argv[])
{
	NF_RULE rule;

#ifdef _DEBUG
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	_CrtSetReportMode( _CRT_ERROR, _CRTDBG_MODE_DEBUG);
#endif

	if (argc < 3)
	{
		printf("Usage: PFHttpRedirector <URL> <new URL>\n" \
			"Redirect HTTP requests with the specified URL to new URL\n");
		return -1;
	}
	
	g_urlString = strToLower(argv[1]);
	g_newUrlString = strToLower(argv[2]);

	nf_adjustProcessPriviledges();

	printf("Press any key to stop...\n\n");

	HttpFilter f;

	if (!pf_init(&f, L"c:\\netfilter2"))
	{
		printf("Failed to initialize protocol filter");
		return -1;
	}

	pf_setRootSSLCertSubject("NFSDK Sample CA");

	// Initialize the library and start filtering thread
	if (nf_init(NFDRIVER_NAME, pf_getNFEventHandler()) != NF_STATUS_SUCCESS)
	{
		printf("Failed to connect to driver");
		return -1;
	}

	// Filter TCP connections
	memset(&rule, 0, sizeof(rule));
	rule.direction = NF_D_OUT;
	rule.protocol = IPPROTO_TCP;
	rule.filteringFlag = NF_FILTER;
	nf_addRule(&rule, TRUE);

	// Block QUIC
	rule.direction = NF_D_BOTH;

	rule.protocol = IPPROTO_UDP;
	rule.remotePort = ntohs(80);
	rule.filteringFlag = NF_BLOCK;
	nf_addRule(&rule, TRUE);

	rule.protocol = IPPROTO_UDP;
	rule.remotePort = ntohs(443);
	rule.filteringFlag = NF_BLOCK;
	nf_addRule(&rule, TRUE);

	// Wait for any key
	getchar();

	// Free the libraries
	nf_free();
	pf_free();

	return 0;
}

