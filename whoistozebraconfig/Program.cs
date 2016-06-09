using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace whoistozebraconfig
{
    class Program
    {
        static void Main(string[] args)
        {
            if(args.Length != 3)
            {
                Console.WriteLine("Require 3 args: ASN Name and Route");
                Console.WriteLine("Example: whoistozebraconfig AS39111 AmazonAWS 10.8.0.5");
                return;
            }

            List<string> whoisData = Whois.Lookup(args[0]);

            var routes = from x in whoisData
                         where x.Contains("route: ")
                         select x.Replace("route:", string.Empty).Trim();

            Console.WriteLine("Found {0} routes", routes.Count());


            Console.WriteLine("! Begin {0} routes", args[1]);
            
            foreach(string s in routes)
            {
                Console.WriteLine("ip route {0} {1}", s, args[2]);
            }

            Console.WriteLine("! End {0} routes",args[1]);

            Console.ReadLine();
        }
    }

    /// <summary>
    /// A class to lookup whois information.
    /// https://coderbuddy.wordpress.com/2010/10/12/a-simple-c-class-to-get-whois-information/
    /// </summary>
    public class Whois
    {
        private const int Whois_Server_Default_PortNumber = 43;
        private const string Domain_Record_Type = "-i origin";
        private const string DotCom_Whois_Server = "whois.radb.net";

        /// <summary>
        /// Retrieves whois information
        /// </summary>
        /// <param name="domainName">The registrar or domain or name server whose whois information to be retrieved</param>
        /// <param name="recordType">The type of record i.e a domain, nameserver or a registrar</param>
        /// <returns></returns>
        public static List<string> Lookup(string domainName)
        {
            using (TcpClient whoisClient = new TcpClient())
            {
                whoisClient.Connect(DotCom_Whois_Server, Whois_Server_Default_PortNumber);

                string domainQuery = Domain_Record_Type + " " + domainName + "\r\n";
                byte[] domainQueryBytes = Encoding.ASCII.GetBytes(domainQuery.ToCharArray());

                Stream whoisStream = whoisClient.GetStream();
                whoisStream.Write(domainQueryBytes, 0, domainQueryBytes.Length);

                StreamReader whoisStreamReader = new StreamReader(whoisClient.GetStream(), Encoding.ASCII);

                string streamOutputContent = "";
                List<string> whoisData = new List<string>();
                while (null != (streamOutputContent = whoisStreamReader.ReadLine()))
                {
                    whoisData.Add(streamOutputContent);
                }

                whoisClient.Close();

                return whoisData;
            }
        }
    }
}
