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

namespace PFHttpContentFilterCS
{
    using ENDPOINT_ID = Int64;

    class Filter : PFEventsDefault
    {
        private string m_titlePrefix = "";

        public void setTitlePrefix(string s)
        {
            m_titlePrefix = s;
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
        }

        private bool updateContent(PFObject obj)
        {
            PFStream pStream = obj.getStream((int)PF_HttpStream.HS_CONTENT);
            bool contentUpdated = false;

            if ((pStream != null) && (pStream.size() > 0))
            {
                string content = loadString(pStream, true);

                int pos = content.IndexOf("<title", StringComparison.OrdinalIgnoreCase);
                if (pos != -1)
                {
                    int pos2 = content.IndexOf('>', pos);
                    if (pos2 != -1)
                    {
                        pStream.reset();
                        pos2++;
                        saveString(pStream, content.Substring(0, pos2), false);
                        saveString(pStream, m_titlePrefix, false);
                        saveString(pStream, content.Substring(pos2), false);

                        contentUpdated = true;
                    }
                }
            }

            return contentUpdated;
        }

        public override void dataAvailable(ulong id, ref PFObject pObject)
        {
            if (pObject.isReadOnly())
                return;

            if ((pObject.getType() == PF_ObjectType.OT_HTTP_RESPONSE) &&
                (pObject.getStreamCount() == 3))
            {
                PFHeader h = PFAPI.pf_readHeader(pObject.getStream((int)PF_HttpStream.HS_HEADER));
                if (h != null)
                {
                    string contentType;

                    contentType = h["Content-Type"];
                    if (contentType != null)
                    {
                        if (!contentType.ToLower().Contains("text/html"))
                        {
                            PFAPI.pf_postObject(id, ref pObject);
                            return;
                        }
                    }
                }

                updateContent(pObject);
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

            if (pObject.getType() == PF_ObjectType.OT_HTTP_RESPONSE)
            {
                PFHeader h = PFAPI.pf_readHeader(pObject.getStream((int)PF_HttpStream.HS_HEADER));

                if (h != null)
                {
                    string contentType;

                    contentType = h["Content-Type"];
                    if (contentType != null)
                    {
                        if (contentType.ToLower().Contains("text/html"))
                        {
                            if (updateContent(pObject))
                            {
                                return PF_DATA_PART_CHECK_RESULT.DPCR_UPDATE_AND_BYPASS;
                            }
                            else
                            {
                                return PF_DATA_PART_CHECK_RESULT.DPCR_MORE_DATA_REQUIRED;
                            }
                        }
                    }
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
            Console.Out.WriteLine("Usage: PFHttpContentFilterCS.exe <string>");
            Console.Out.WriteLine("<string> : add this to titles of HTML pages");
        }

        unsafe static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                usage();
                return;
            }

            m_filter.setTitlePrefix(args[0]);

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
