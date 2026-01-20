using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using pfapinet;
using nfapinet;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace PFHttpBlockerCS
{
    using ENDPOINT_ID = Int64;

    class Filter : PFEventsDefault
    {
        private string m_blockString = "";
        private string m_blockPage = "<html><body>blocked</body></html>";

        public void setBlockString(string s)
        {
            m_blockString = s;
        }

        public unsafe string loadString(PFStream pStream, bool seekToBegin)
        {
            if (pStream == null || pStream.size() == 0)
                return "";

            byte[] buf = new byte[pStream.size() + 1];
            uint len = 0;

            if (seekToBegin)
            {
                pStream.seek(0, (int)SeekOrigin.Begin);
            }

            fixed (byte* p = buf)
            {
                len = pStream.read((IntPtr)p, (uint)pStream.size());

                char[] cbuf = new char[len];

                for (int i = 0; i < len; i++)
                {
                    cbuf[i] = (char)buf[i];
                }

                return new String(cbuf);
            }
        }

        unsafe bool saveString(PFStream pStream, string s, bool clearStream)
        {
            if (pStream == null)
                return false;

            if (clearStream)
            {
                pStream.reset();
            }

            foreach (char c in s.ToCharArray())
            {
                byte b = (byte)c;
                if (pStream.write((IntPtr)(byte*)&b, (uint)1) < 1)
                    return false;
            }
            return true;
        }

        public override void tcpConnected(ulong id, NF_TCP_CONN_INFO pConnInfo)
        {
            PFAPI.pf_addFilter(id,
                PF_FilterType.FT_PROXY,
                PF_FilterFlags.FF_READ_ONLY_IN | PF_FilterFlags.FF_READ_ONLY_OUT,
                PF_OpTarget.OT_LAST,
                PF_FilterType.FT_NONE);

            PFAPI.pf_addFilter(id,
                PF_FilterType.FT_SSL,
                PF_FilterFlags.FF_SSL_INDICATE_HANDSHAKE_REQUESTS | PF_FilterFlags.FF_SSL_VERIFY,
                PF_OpTarget.OT_LAST,
                PF_FilterType.FT_NONE);

            PFAPI.pf_addFilter(id,
                PF_FilterType.FT_HTTP,
                PF_FilterFlags.FF_HTTP_BLOCK_SPDY,
                PF_OpTarget.OT_LAST,
                PF_FilterType.FT_NONE);
        
            PFAPI.pf_addFilter(id,
                PF_FilterType.FT_HTTP2,
                PF_FilterFlags.FF_DEFAULT,
                PF_OpTarget.OT_LAST,
                PF_FilterType.FT_NONE);

        }

        public string getHttpUrl(PFObject pObject)
        {
            string url = "", status, host, uri;

            if (pObject.getType() == PF_ObjectType.OT_HTTP_REQUEST ||
                pObject.getType() == PF_ObjectType.OT_HTTP_RESPONSE)
            {
                try
                {

                    PFHeader h = PFAPI.pf_readHeader(pObject.getStream((int)PF_HttpStream.HS_HEADER));

                    if (pObject.getType() == PF_ObjectType.OT_HTTP_REQUEST)
                    {
                        host = h["Host"];
                        status = loadString(pObject.getStream((int)PF_HttpStream.HS_STATUS), true);
                    }
                    else
                    {
                        host = h[CustomHTTPHeaders.HTTP_EXHDR_RESPONSE_HOST];
                        status = h[CustomHTTPHeaders.HTTP_EXHDR_RESPONSE_REQUEST];
                    }

                    int pos = status.IndexOf(' ');
                    if (pos != -1)
                    {
                        pos++;

                        int pEnd = status.IndexOf(' ', pos);

                        if (pEnd != -1)
                        {
                            uri = status.Substring(pos, pEnd - pos);
                            if (uri.StartsWith("http://"))
                            {
                                url = uri;
                            }
                            else
                            {
                                url = "http://" + host + uri;
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    url = "";
                }
            } else
            if (pObject.getType() == PF_ObjectType.OT_HTTP2_REQUEST ||
                pObject.getType() == PF_ObjectType.OT_HTTP2_RESPONSE)
            {
                try
                {

                    PFHeader h = PFAPI.pf_readHeader(pObject.getStream((int)PF_Http2Stream.H2S_HEADER));

                    if (pObject.getType() == PF_ObjectType.OT_HTTP2_REQUEST)
                    {
                        host = h[":authority"];
                        uri = h[":path"];
                    }
                    else
                    {
                        host = h[CustomHTTP2Headers.HTTP2_EXHDR_AUTHORITY];
                        uri = h[CustomHTTP2Headers.HTTP2_EXHDR_PATH];
                    }

                    url = "http://" + host + uri;
                }
                catch (Exception)
                {
                    url = "";
                }
            }
                
            return url;
        }

        void postBlockHttpResponse(ulong id)
        {
            PFObject obj = PFObject.create(PF_ObjectType.OT_HTTP_RESPONSE, 3);

            saveString(obj.getStream((int)PF_HttpStream.HS_STATUS), "HTTP/1.1 404 Not OK\r\n", true);

            PFHeader h = new PFHeader();
            h.Add("Content-Type", "text/html");
            h.Add("Content-Length", Convert.ToString(m_blockPage.Length));
            h.Add("Connection", "close");

            PFAPI.pf_writeHeader(obj.getStream((int)PF_HttpStream.HS_HEADER), h);

            saveString(obj.getStream((int)PF_HttpStream.HS_CONTENT), m_blockPage, true);

            PFAPI.pf_postObject(id, ref obj);

            obj.free();
        }

        void postBlockHttp2Response(ulong id, PFObject origObject)
        {
            PFObject obj = PFObject.create(PF_ObjectType.OT_HTTP2_RESPONSE, 3);

            PFStream origStream = origObject.getStream((int)PF_Http2Stream.H2S_INFO);
            PFStream stream = obj.getStream((int)PF_Http2Stream.H2S_INFO);
            // Copy stream id
            origStream.copyTo(ref stream);

            PFHeader h = new PFHeader();
            h.Add(":status", "404");
            h.Add("content-type", "text/html");
            h.Add("content-length", Convert.ToString(m_blockPage.Length));
            h.Add("connection", "close");

            PFAPI.pf_writeHeader(obj.getStream((int)PF_Http2Stream.H2S_HEADER), h);

            saveString(obj.getStream((int)PF_Http2Stream.H2S_CONTENT), m_blockPage, true);

            PFAPI.pf_postObject(id, ref obj);

            obj.free();
        }

        public override void dataAvailable(ulong id, ref PFObject pObject)
        {
            if (pObject.isReadOnly())
                return;

            if (pObject.getType() == PF_ObjectType.OT_HTTP_REQUEST ||
                pObject.getType() == PF_ObjectType.OT_HTTP2_REQUEST)
            {
                string url = getHttpUrl(pObject).ToLower();

                if (url.Contains(m_blockString))
                {
	                if (pObject.getType() == PF_ObjectType.OT_HTTP_REQUEST)
    	            {
        	            postBlockHttpResponse(id);
            	    } else
                	if (pObject.getType() == PF_ObjectType.OT_HTTP2_REQUEST)
	                {
    	                postBlockHttp2Response(id, pObject);
        	        }
                    
                    return;
                }
            }

            PFAPI.pf_postObject(id, ref pObject);
        }

        public override PF_DATA_PART_CHECK_RESULT dataPartAvailable(ulong id, ref PFObject pObject)
        {
            if (pObject.getType() == PF_ObjectType.OT_SSL_HANDSHAKE_OUTGOING)
            {
                PFStream pStream = pObject.getStream(0);
                PF_DATA_PART_CHECK_RESULT res = PF_DATA_PART_CHECK_RESULT.DPCR_FILTER;

                if (pStream != null && pStream.size() > 0)
                {
                    string domainName = loadString(pStream, true);

                    if (domainName.ToLower().Contains("get.adobe.com"))
                    {
                        res = PF_DATA_PART_CHECK_RESULT.DPCR_BYPASS;
                    }
                }
                return res;
            }

            if (pObject.getType() == PF_ObjectType.OT_HTTP_REQUEST ||
                pObject.getType() == PF_ObjectType.OT_HTTP2_REQUEST)
            {
                string url = getHttpUrl(pObject).ToLower();

                if (url.Contains(m_blockString))
                {
                    if (pObject.getType() == PF_ObjectType.OT_HTTP_REQUEST)
                    {
                        postBlockHttpResponse(id);
                    } else
                    if (pObject.getType() == PF_ObjectType.OT_HTTP2_REQUEST)
                    {
                        postBlockHttp2Response(id, pObject);
                    }

                    return PF_DATA_PART_CHECK_RESULT.DPCR_BLOCK;
                }
            }

            return PF_DATA_PART_CHECK_RESULT.DPCR_BYPASS;
        }
    }

    class Program
    {
        static Filter m_filter = new Filter();

        static void usage()
        {
            Console.Out.WriteLine("Usage: PFHttpBlockerCS.exe <block string>");
            Console.Out.WriteLine("<block string> : block the requests having the specified substring in URL");
        }

        unsafe static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                usage();
                return;
            }

            m_filter.setBlockString(args[0].ToLower());

            if (!PFAPI.pf_init(m_filter, "c:\\netfilter2"))
                return;

            PFAPI.pf_setRootSSLCertSubject("NFSDK Sample CA");

            if (NFAPI.nf_init(nfapinet.samples_config.getDriverName(), PFAPI.pf_getNFEventHandler()) != 0)
            {
                PFAPI.pf_free();
                return;
            }

            NFAPI.nf_setTCPTimeout(0);

            NF_RULE rule = new NF_RULE();

            // Do not filter local traffic
            rule.filteringFlag = (uint)NF_FILTERING_FLAG.NF_ALLOW;
            rule.ip_family = (ushort)AddressFamily.InterNetwork;
            rule.remoteIpAddress = IPAddress.Parse("127.0.0.1").GetAddressBytes();
            rule.remoteIpAddressMask = IPAddress.Parse("255.0.0.0").GetAddressBytes();
            NFAPI.nf_addRule(rule, 0);

            rule = new NF_RULE();
            // Filter outgoing TCP connections 
            rule.direction = (byte)NF_DIRECTION.NF_D_OUT;
            rule.protocol = (int)ProtocolType.Tcp;
            rule.filteringFlag = (uint)NF_FILTERING_FLAG.NF_FILTER;
            NFAPI.nf_addRule(rule, 0);

            // Disable QUIC protocol to make the browsers switch to generic HTTP

            rule = new NF_RULE();
            rule.protocol = (int)ProtocolType.Udp;
            rule.remotePort = (ushort)IPAddress.HostToNetworkOrder((Int16)80);
            rule.filteringFlag = (uint)NF_FILTERING_FLAG.NF_BLOCK;
            NFAPI.nf_addRule(rule, 0);

            rule = new NF_RULE();
            rule.protocol = (int)ProtocolType.Udp;
            rule.remotePort = (ushort)IPAddress.HostToNetworkOrder((Int16)443);
            rule.filteringFlag = (uint)NF_FILTERING_FLAG.NF_BLOCK;
            NFAPI.nf_addRule(rule, 0);

            Console.In.ReadLine();

            NFAPI.nf_free();
            PFAPI.pf_free();
        }
    }
}
