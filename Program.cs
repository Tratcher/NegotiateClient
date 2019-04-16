using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Principal;
using System.Threading.Tasks;

namespace NegotiateStreamClient
{
    class Program
    {
        static void Main(string[] args)
        {
            var controlPort = 54321;
            var controlIp = IPAddress.IPv6Any;
            if (args.Length > 0)
            {
                controlPort = int.Parse(args[0]);
            }
            if (args.Length > 1)
            {
                controlIp = IPAddress.Parse(args[1]);
            }
            RunControlChannel(new IPEndPoint(controlIp, controlPort));
        }

        private static void RunControlChannel(IPEndPoint controlEndPoint)
        {
            try
            {
                Console.WriteLine($"Control channel listening on {controlEndPoint}");
                var listener = new TcpListener(controlEndPoint);
                if (controlEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    listener.Server.DualMode = true;
                }
                listener.Start();

                while (true)
                {
                    Console.WriteLine("Accepting control channel...");
                    var client = listener.AcceptTcpClient();
                    // Fire and forget, accept the next incoming.
                    ProcessIncoming(client);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        private static async void ProcessIncoming(TcpClient client)
        {
            using (client)
            {
                try
                {
                    var serverEndPoint = (IPEndPoint)client.Client.RemoteEndPoint;
                    var dns = await Dns.GetHostEntryAsync(serverEndPoint.Address);

                    string serverSpn = "HOST/" + dns.HostName;
                    await ClientAuth(client, serverSpn);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex);
                }
            }
        }

        private static async Task ClientAuth(TcpClient tcpClient, string serverSpn)
        {
            try
            {
                using (var clientAuth = new NegotiateStream(tcpClient.GetStream(), leaveInnerStreamOpen: false))
                {
                    Console.WriteLine($"Authenticating to {serverSpn}");
                    await clientAuth.AuthenticateAsClientAsync(
                        CredentialCache.DefaultNetworkCredentials,
                        serverSpn,
                        ProtectionLevel.EncryptAndSign,
                        TokenImpersonationLevel.Identification);

                    Console.WriteLine("Authenticated");
                    Console.WriteLine($"IsAuthenticated: {clientAuth.IsAuthenticated}");
                    Console.WriteLine($"IsEncrypted: {clientAuth.IsEncrypted}");
                    Console.WriteLine($"IsMutuallyAuthenticated: {clientAuth.IsMutuallyAuthenticated}");
                    Console.WriteLine($"IsSigned: {clientAuth.IsSigned}");
                    Console.WriteLine($"AuthType: {clientAuth.RemoteIdentity.AuthenticationType}");
                    Console.WriteLine($"Name: {clientAuth.RemoteIdentity.Name}");

                    // Send a message to the server.
                    var message = "Hello from the client.";
                    using (var writer = new StreamWriter(clientAuth))
                    {
                        await writer.WriteAsync(message);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }
    }
}
