using System;
using System.Net;
using SnmpSharpNet;
using System.Text;




namespace sharpwalk
{
    class Program
    {
        public static String parseDateAndTimeOctet(OctetString v)
        {



            //OctetString

            byte[] bts = v.ToArray();

            byte[] format_str = new byte[128];   //保存格式化过后的时间字符串

            int year;

            int month;

            int day;

            int hour;

            int minute;

            int second;

            //int msecond;      
            year = year = bts[0] * 256 + bts[1];
            month = bts[2];
            day = bts[3];
            hour = bts[4];
            minute = bts[5];
            second = bts[6];
            //msecond = bts[7];
            //以下为格式化字符串
            int index = 3;
            int temp = year;

            for (; index >= 0; index--)
            {
                format_str[index] = (byte)(48 + (temp - temp / 10 * 10));
                temp /= 10;
            }

            format_str[4] = (Byte)'-';
            index = 6;
            temp = month;
            for (; index >= 5; index--)
            {
                format_str[index] = (byte)(48 + (temp - temp / 10 * 10));
                temp /= 10;
            }

            format_str[7] = (Byte)'-';
            index = 9;
            temp = day;
            for (; index >= 8; index--)
            {

                format_str[index] = (byte)(48 + (temp - temp / 10 * 10));

                temp /= 10;

            }
            format_str[10] = (Byte)' ';
            index = 12;
            temp = hour;
            for (; index >= 11; index--)
            {
                format_str[index] = (byte)(48 + (temp - temp / 10 * 10));
                temp /= 10;
            }

            format_str[13] = (Byte)':';
            index = 15;
            temp = minute;
            for (; index >= 14; index--)
            {

                format_str[index] = (byte)(48 + (temp - temp / 10 * 10));

                temp /= 10;

            }

            format_str[16] = (Byte)':';
            index = 18;
            temp = second;
            for (; index >= 17; index--)
            {
                format_str[index] = (byte)(48 + (temp - temp / 10 * 10));

                temp /= 10;

            }

            //int i = 6;
            //while (i >= 0)
            //{
            //    Console.WriteLine("{0}", bts[i]);
            //    i--;
            //}

            return System.Text.Encoding.Default.GetString(format_str);// new String(format_str);

        }


        static void Main(string[] args)
        {
            // SNMP community name
            OctetString community = new OctetString("public");
            // Define agent parameters class
            AgentParameters param = new AgentParameters(community);
            // Set SNMP version to 2 (GET-BULK only works with SNMP ver 2 and 3)
            param.Version = SnmpVersion.Ver2;
            // Construct the agent address object
            // IpAddress class is easy to use here because
            //  it will try to resolve constructor parameter if it doesn't
            //  parse to an IP address
            IpAddress agent = new IpAddress("127.0.0.1");
            // Construct target
            UdpTarget target = new UdpTarget((IPAddress)agent, 161, 2000, 1);
            // Define Oid that is the root of the MIB
            //  tree you wish to retrieve
            Oid rootOid = new Oid(".1.3.6.1.2.1.25.6.3.1"); // ifDescr
            // This Oid represents last Oid returned by
            //  the SNMP agent
            Oid lastOid = (Oid)rootOid.Clone();
            // Pdu class used for all requests
            Pdu pdu = new Pdu(PduType.GetBulk);
            // In this example, set NonRepeaters value to 0
            pdu.NonRepeaters = 0;
            // MaxRepetitions tells the agent how many Oid/Value pairs to return
            // in the response.
            pdu.MaxRepetitions = 5;
            // Loop through results
            while (lastOid != null)
            {
                // When Pdu class is first constructed, RequestId is set to 0
                // and during encoding id will be set to the random value
                // for subsequent requests, id will be set to a value that
                // needs to be incremented to have unique request ids for each
                // packet
                if (pdu.RequestId != 0)
                {
                    pdu.RequestId += 1;
                }
                // Clear Oids from the Pdu class.
                pdu.VbList.Clear();
                // Initialize request PDU with the last retrieved Oid
                pdu.VbList.Add(lastOid);
                // Make SNMP request
                SnmpV2Packet result = (SnmpV2Packet)target.Request(pdu, param);
                // You should catch exceptions in the Request if using in real application.
                // If result is null then agent didn't reply or we couldn't parse the reply.
                if (result != null)
                {
                    // ErrorStatus other then 0 is an error returned by
                    // the Agent - see SnmpConstants for error definitions
                    if (result.Pdu.ErrorStatus != 0)
                    {
                        // agent reported an error with the request
                        Console.WriteLine("Error in SNMP reply. Error {0} index {1}",
                            result.Pdu.ErrorStatus,
                            result.Pdu.ErrorIndex);
                        lastOid = null;
                        break;
                    }
                    else
                    {
                        // Walk through returned variable bindings
                        foreach (Vb v in result.Pdu.VbList)
                        {
                            // Check that retrieved Oid is "child" of the root OID
                            if (rootOid.IsRootOf(v.Oid))
                            {

                                if (v.Oid.ToString().Contains("1.3.6.1.2.1.25.6.3.1.2"))
                                {
                                    if (((OctetString)v.Value).IsHex)
                                    {
                                        byte[] bs = ((OctetString)v.Value).ToArray();
                                        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
                                        Console.WriteLine("{0} ({1}): {2}",
                                        v.Oid.ToString(),
                                        SnmpConstants.GetTypeName(v.Value.Type), Encoding.GetEncoding("GBK").GetString(bs)
);
                                    }
                                    else
                                    {
                                        Console.WriteLine("{0} ({1}): {2}",
                                        v.Oid.ToString(),
                                        SnmpConstants.GetTypeName(v.Value.Type), v.Value.ToString());
                                    }



                                }
                                if (v.Oid.ToString().Contains("1.3.6.1.2.1.25.6.3.1.5"))
                                {


                                    Console.WriteLine("{0} ({1}): {2}",
                                    v.Oid.ToString(),
                                    SnmpConstants.GetTypeName(v.Value.Type),
                                    parseDateAndTimeOctet((OctetString)v.Value));
                                }
                                if (v.Value.Type == SnmpConstants.SMI_ENDOFMIBVIEW)
                                    lastOid = null;
                                else
                                    lastOid = v.Oid;


                            }
                            else
                            {
                                // we have reached the end of the requested
                                // MIB tree. Set lastOid to null and exit loop
                                lastOid = null;
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("No response received from SNMP agent.");
                }
            }
            target.Close();
        }
    }
}