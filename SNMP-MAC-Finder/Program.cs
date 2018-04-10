using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using SnmpSharpNet;

namespace SNMPHaxk
{
    class Program
    {
        private static string CPEBase = "10.20.31.2";

        public static string[] Switches =
        {
            "10.20.31.226", "10.20.31.227", "10.20.31.228", "10.20.31.229",
            "10.20.31.230", "10.20.31.231", "10.20.31.232", "10.20.31.233", "10.20.31.234", "10.20.31.235", "10.20.31.236", "10.20.31.237", "10.20.31.238", "10.20.31.239",
            "10.20.31.240"
        };

        static void Main(string[] args)
        {
            Console.Write("Please enter mac address: ");
            string input = Console.ReadLine();
            var parts = input?.Split(':');

            if (parts == null || parts.Length != 6)
            {
                Console.WriteLine("Invalid MAC: use format \"AA:BB:CC:DD:EE:FF\"");
                Console.ReadLine();
                return;
            }

            StringBuilder mac = new StringBuilder();

            foreach (var part in parts)
            {
                mac.Append($".{Convert.ToInt16(part, 16)}");
            }

            foreach (var sw in Switches)
            {
                int port = SNMPGet(mac.ToString(), sw);
                Console.WriteLine($"{input} is at port: {port} on {sw}");
            }
        }
        
        static int SNMPGet(string mac, string ip)
        {
            // SNMP community name
            OctetString community = new OctetString("public");

            // Define agent parameters class
            AgentParameters param = new AgentParameters(community);
            // Set SNMP version to 1 (or 2)
            param.Version = SnmpVersion.Ver2;
            // Construct the agent address object
            // IpAddress class is easy to use here because
            //  it will try to resolve constructor parameter if it doesn't
            //  parse to an IP address
            IpAddress agent = new IpAddress(ip);

            UdpTarget target = new UdpTarget((IPAddress)agent, 161, 2000, 1);

            Oid rootOid = new Oid(".1.3.6.1.2.1.17.7.1.2.2.1.2.1");  // dot1qTpFdbPort, .iso.org.dod.internet.mgmt.mib-2.dot1dBridge.qBridgeMIB.qBridgeMIBObjects.dot1qTp.dot1qTpFdbTable.dot1qTpFdbEntry.dot1qTpFdbPort
            Oid lastOid = (Oid)rootOid.Clone();

            Pdu pdu = new Pdu(PduType.GetNext);

            while (lastOid != null)
            {
                // When Pdu class is first constructed, RequestId is set to a random value
                // that needs to be incremented on subsequent requests made using the
                // same instance of the Pdu class.
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
                                /*
                                Console.WriteLine("{0} ({1}): {2}",
                                    v.Oid.ToString(),
                                    SnmpConstants.GetTypeName(v.Value.Type),
                                    v.Value.ToString());
                                 */
                                if (v.Oid.ToString().EndsWith(mac))
                                {
                                    target.Close();
                                    return Convert.ToInt32(v.Value.ToString());

                                }
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
            return -1;
        }
    }
}
