// Blocks FTP uploads by content substring
//

#include "stdafx.h"
#include <crtdbg.h>
#include <queue>
#include "ProtocolFilters.h"
#include "PFEventsDefault.h"

#include "samples_config.h"

#pragma comment(lib,"ws2_32.lib")

using namespace nfapi;
using namespace ProtocolFilters;

std::string g_blockString;
tStreamSize g_maxFileSize = 100 * 1024 * 1024;

static bool appendStreamContent(PFStream * streamFrom, PFStream * streamTo)
{
	char tempBuf[1000];
	tStreamSize nBytes;
	
	streamTo->seek(0, FILE_END);
	streamFrom->seek(0, FILE_BEGIN);

	for (;;)
	{
		nBytes = streamFrom->read(tempBuf, sizeof(tempBuf));
		if (nBytes == 0)
			break;

		if (streamTo->write(tempBuf, nBytes) != nBytes)
			return false;
	}

	return true;
}

static inline bool _splitString(const std::string & s, 
				 std::vector<std::string> & parts, 
				 const char * dividers)
{
	std::string part;
	
	parts.clear();

	for (size_t i=0; i<s.length(); i++)
	{
		if (strchr(dividers, s[i]) != 0)
		{
			if (!part.empty())
			{
				parts.push_back(part);
				part.erase();
			}
		} else
		{
			part += s[i];
		}
	}
	if (!part.empty())
	{
		parts.push_back(part);
		part.erase();
	}
	return true;
}

static PFObject * createObject(tPF_ObjectType type, int nStreams, const std::string & content)
{
	PFObject * object = PFObject_create(type, nStreams);
	
	if (!object)
		return NULL;
	
	if (content.length() > 0)
	{
		object->getStream(0)->write(content.c_str(), (tStreamSize)content.length());
	}
	
	return object;
}

static bool postCmdData(nfapi::ENDPOINT_ID id, tPF_ObjectType type, const std::string & content)
{
	if (type == OT_FTP_COMMAND)
	{
		printf("Post request: %s\n", content.c_str());
	} else
	{
		printf("Post response: %s\n", content.c_str());
	}

	std::string data = content + "\n";

	PFObject * obj = createObject(type, 2, data);
	if (!obj)
		return false;
	
	pf_postObject(id, obj);
	
	obj->free();

	return true;
}

static bool loadStream(PFStream * pStream, std::string & value)
{
	if (!pStream || pStream->size() == 0)
		return false;

	value.resize((unsigned int)pStream->size());

	pStream->seek(0, FILE_BEGIN);

	return pStream->read((char*)value.c_str(), (tStreamSize)value.length()) == (tStreamSize)value.length();
}

static bool bufferContansString(const char * buf, int bufLen, const char * str, int strLen)
{
	for (int i = 0; i < bufLen-strLen; i++)
	{
		if (memcmp((void*)(buf+i), str, strLen) == 0)
			return true;
	}

	return false;
}

static bool bufferMustBeBlocked(PFObject * object)
{
	tStreamPos len;
	PFStream * stream;
	bool result = false;

	stream = object->getStream(0);

	len = stream->size();

	char * tempBuf;
	tStreamSize nBytes;
	
	tempBuf = (char*)malloc((size_t)len+1);
	if (!tempBuf)
		return false;

	for (;;)
	{
		stream->seek(0, FILE_BEGIN);

		nBytes = stream->read(tempBuf, (tStreamSize)len);
		if (nBytes != len)
			break;

		tempBuf[len] = '\0';

		if (bufferContansString(tempBuf, (int)len, 
				g_blockString.c_str(), (int)g_blockString.length()))
		{
			result = true;
		}

		break;
	}

	free(tempBuf);

	return result;
}

class FTPObjectInfo
{
public:
	FTPObjectInfo()
	{
	}
	FTPObjectInfo(const FTPObjectInfo & v)
	{
		*this = v;
	}
	FTPObjectInfo & operator = (const FTPObjectInfo & v)
	{
		command = v.command;
		fileName = v.fileName;
		sessionId = v.sessionId;
		return *this;
	}

	std::string command;
	std::string fileName;
	ENDPOINT_ID sessionId;
};

static bool getObjectInfo(PFObject * object, FTPObjectInfo & objectInfo)
{
	PFHeader h;

	if (!pf_readHeader(object->getStream(1), &h))
		return false;

	PFHeaderField * pField;
	std::string cmd;

	pField = h.findFirstField("COMMAND");
	if (pField)
	{
		cmd = pField->value();

		objectInfo.command = cmd;

		size_t pos = cmd.find(" ");
		if (pos != std::string::npos)
		{
			objectInfo.fileName = cmd.substr(pos+1);
		}
	}


	pField = h.findFirstField("SESSIONID");
	if (pField)
	{
		objectInfo.sessionId = atoi(pField->value().c_str());
	}
 
	return true;
}

class FtpFilter : public PFEventsDefault
{
public:
	FtpFilter()
	{
	}
	~FtpFilter()
	{
		clear();
	}

	void clear()
	{
		tDataInfoMap::iterator it;
		for (it = m_dataInfoMap.begin(); it != m_dataInfoMap.end(); it++)
		{
			it->second.buffer->free();
		}
		m_dataInfoMap.clear();

		tCmdInfoMap::iterator itc;
		for (itc = m_cmdInfoMap.begin(); itc != m_cmdInfoMap.end(); itc++)
		{
			itc->second.clear();
		}
		m_cmdInfoMap.clear();
	}

	void tcpConnected(nfapi::ENDPOINT_ID id, nfapi::PNF_TCP_CONN_INFO pConnInfo)
	{
		pf_addFilter(id, FT_PROXY);
		pf_addFilter(id, FT_SSL, FF_SSL_TLS_AUTO);
		pf_addFilter(id, FT_FTP, FF_SSL_TLS);
	}

	void tcpClosed(nfapi::ENDPOINT_ID id, nfapi::PNF_TCP_CONN_INFO pConnInfo)
	{
		tDataInfoMap::iterator it;
		it = m_dataInfoMap.find(id);
		if (it != m_dataInfoMap.end())
		{
			it->second.buffer->free();
			m_dataInfoMap.erase(it);
		}

		tCmdInfoMap::iterator itc;
		itc = m_cmdInfoMap.find(id);
		if (itc != m_cmdInfoMap.end())
		{
			itc->second.clear();
			m_cmdInfoMap.erase(itc);
		}
	}

	void dataAvailable(nfapi::ENDPOINT_ID id, PFObject * object)
	{
		if (object->isReadOnly())
		{
			return;
		}

		if (object->getType() == OT_FTP_COMMAND)
		{
			FTP_CMD_INFO * pci;
			tCmdInfoMap::iterator itc = m_cmdInfoMap.find(id);

			if (itc != m_cmdInfoMap.end())
			{
				pci = &itc->second;
			} else
			{
				FTP_CMD_INFO ci;
				ci.nWaitingResponses = 0;
				ci.filterCmdData = false;
				ci.requests = new tStringQueue();
				ci.pendedRequests = new tStringQueue();
			
				pci = &m_cmdInfoMap.insert(tCmdInfoMap::value_type(id, ci)).first->second;
			}

			std::string request;
			std::vector<std::string> parts;
			
			if (!loadStream(object->getStream(0), request))
			{
				pf_postObject(id, object);
				return;
			}

			_splitString(request, parts, "\n");

			for (size_t i=0; i<parts.size(); i++)
			{
				if (!pci->requests->empty())
				{
					printf("pended request %s\n", parts[i].c_str());
					pci->pendedRequests->push(parts[i]);
				} else
				{
					printf("request %s\n", parts[i].c_str());
					postCmdData(id, OT_FTP_COMMAND, parts[i]);
				}
			}

			return;
		}

		if (object->getType() == OT_FTP_RESPONSE)
		{
			tCmdInfoMap::iterator itc = m_cmdInfoMap.find(id);

			if (itc != m_cmdInfoMap.end())
			{
				std::string response;
				std::vector<std::string> parts;

				if (!loadStream(object->getStream(0), response))
				{
					pf_postObject(id, object);
					return;
				}

				_splitString(response, parts, "\n");

				for (size_t i=0; i<parts.size(); i++)
				{
					printf("response %s\n", parts[i].c_str());

					printf("nWaitingResponses = %d\n", itc->second.nWaitingResponses);

					if (strncmp(parts[i].c_str(), "150", 3) == 0)
					{
						postCmdData(id, OT_FTP_RESPONSE, parts[i]);
						continue;
					} 
					
					if (itc->second.requests->empty())
					{
						postCmdData(id, OT_FTP_RESPONSE, parts[i]);
						continue;
					}

					if (itc->second.nWaitingResponses > 0)
					{
						itc->second.nWaitingResponses--;

						postCmdData(id, OT_FTP_RESPONSE, parts[i]);
					} else
					if (!itc->second.requests->empty())
					{
						itc->second.requests->pop();
					}
				}

				if (itc->second.nWaitingResponses == 0)
				{
					if (!itc->second.requests->empty())
					{
						std::string s = itc->second.requests->front();
						postCmdData(id, OT_FTP_COMMAND, s);
					} else
					if (!itc->second.pendedRequests->empty())
					{
						std::string s = itc->second.pendedRequests->front();

						postCmdData(id, OT_FTP_COMMAND, s);

						itc->second.pendedRequests->pop();
						itc->second.nWaitingResponses++;
					}
				}

				return;
			}

		}

		if (object->getType() == OT_TCP_DISCONNECT_LOCAL)
		{
			tDataInfoMap::iterator it;
			FTP_DATA_INFO di;

			it = m_dataInfoMap.find(id);
			if (it != m_dataInfoMap.end())
			{
				if (it->second.filteringDisabled)
				{
					it->second.buffer->free();
					m_dataInfoMap.erase(it);
					pf_postObject(id, object);
					return;
				}

				di = it->second;

				if (bufferMustBeBlocked(di.buffer))
				{
					FTPObjectInfo objectInfo;

					if (getObjectInfo(di.buffer, objectInfo))
					{
						printf("Blocked file name: %s\n", objectInfo.fileName.c_str());
						printf("Command session id: %I64u\n", objectInfo.sessionId);

						tCmdInfoMap::iterator itc = m_cmdInfoMap.find(objectInfo.sessionId);

						if (itc != m_cmdInfoMap.end())
						{
							itc->second.requests->push("DELE "+objectInfo.fileName+"\r");
							itc->second.nWaitingResponses = 1;
						}
					}

					it->second.buffer->free();
					m_dataInfoMap.erase(it);
			
					pf_postObject(id, object);
					return;
				} else
				{
					pf_postObject(id, di.buffer);
				}

				it->second.buffer->free();
				m_dataInfoMap.erase(it);
			}

			pf_postObject(id, object);
			return;
		} 

		if (object->getType() == OT_FTP_DATA_PART_OUTGOING)
		{
			tDataInfoMap::iterator it;
			FTP_DATA_INFO di;

			it = m_dataInfoMap.find(id);
			if (it == m_dataInfoMap.end())
			{
				di.buffer = PFObject_create(OT_FTP_DATA_PART_OUTGOING, 2);
				if (!di.buffer)
				{
					pf_postObject(id, object);
					return;
				}

				if (g_maxFileSize == 0)
					di.buffer->setReadOnly(true);

				object->getStream(1)->copyTo(di.buffer->getStream(1));

				FTPObjectInfo objectInfo;

				if (getObjectInfo(di.buffer, objectInfo))
				{
					printf("File name: %s\n", objectInfo.fileName.c_str());
					printf("Command session id: %I64u\n", objectInfo.sessionId);
				}

				di.filteringDisabled = false;

				m_dataInfoMap[id] = di;
			} else
			{
				di = it->second;
			}

			if (!di.filteringDisabled)
			{
				PFStream * bufferStream = di.buffer->getStream(0);
				PFStream * objectStream = object->getStream(0);

				if (!appendStreamContent(objectStream, bufferStream))
				{
					pf_postObject(id, object);
					return;
				}

				if (g_maxFileSize > 0)
				{
					if (bufferStream->size() > g_maxFileSize)
					{
						printf("File is too large, bypass\n");

						pf_postObject(id, di.buffer);

						di.filteringDisabled = true;
						m_dataInfoMap[id] = di;
					}
				
					return;
				}
			}
		} 

		pf_postObject(id, object);
	}

	PF_DATA_PART_CHECK_RESULT 
	dataPartAvailable(nfapi::ENDPOINT_ID id, PFObject * object)
	{
		return DPCR_BYPASS;
	}

private:

	struct FTP_DATA_INFO
	{
		PFObject * buffer;
		bool filteringDisabled;
	};

	typedef std::map<ENDPOINT_ID, FTP_DATA_INFO> tDataInfoMap;
	tDataInfoMap m_dataInfoMap;

	typedef std::queue<std::string> tStringQueue;

	struct FTP_CMD_INFO
	{
		void clear()
		{
			if (pendedRequests)
			{
				delete pendedRequests;
				pendedRequests = NULL;
			}
			if (requests)
			{
				delete requests;
				requests = NULL;
			}
		}

		tStringQueue * requests;
		tStringQueue * pendedRequests;

		int nWaitingResponses;
		bool filterCmdData;
	};

	typedef std::map<ENDPOINT_ID, FTP_CMD_INFO> tCmdInfoMap;
	tCmdInfoMap m_cmdInfoMap;
};

int main(int argc, char* argv[])
{
	NF_RULE rule;

#ifdef _DEBUG
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	_CrtSetReportMode( _CRT_ERROR, _CRTDBG_MODE_DEBUG);
#endif

	if (argc < 2)
	{
		printf("Usage: PFFtpBlocker <string> <file size limit>\n" \
			"<string> : block the uploaded files with this string in content\n" \
			"<file size limit> : maximum file size (0 or unspecified - no limit)\n");
		return -1;
	}
	
	g_blockString = strToLower(argv[1]);
	printf("Blocking files containing '%s'\n", g_blockString.c_str());
	
	if (argc < 3)
	{
		g_maxFileSize = 0;
	} else
	{
		g_maxFileSize = atoi(argv[2]);
		printf("Files larger than %d are not blocked\n", g_maxFileSize);
	}

	nf_adjustProcessPriviledges();

	printf("Press enter to stop...\n\n");

	FtpFilter f;

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

	// Filter all TCP connections
	memset(&rule, 0, sizeof(rule));
	rule.protocol = IPPROTO_TCP;
	rule.filteringFlag = NF_FILTER;
	nf_addRule(&rule, TRUE);

	// Wait for any key
	getchar();

	// Free the libraries
	nf_free();
	pf_free();

	return 0;
}

