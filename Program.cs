using System;
using System.IO;
using System.Reflection;
using System.Text;
using System.Web.Security;

namespace FormsTicketTool
{
    // Enjoy this vibe coded program. I have no idea of what's happening, good luck if it does not works as expected.
    class Program
    {
        static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                PrintUsage();
                return 1;
            }

            var mode = args[0].Trim().ToLowerInvariant();
            try
            {
                switch (mode)
                {
                    case "decrypt":
                        return HandleDecrypt(args);
                    case "encrypt":
                        return HandleEncrypt(args);
                    default:
                        Console.Error.WriteLine("Unknown mode: " + mode);
                        PrintUsage();
                        return 1;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error: " + ex.Message);
                return 1;
            }
        }

        private static int HandleDecrypt(string[] args)
        {
            // decrypt <validationKey> <decryptionKey> <encryptedTicket>
            if (args.Length < 4)
            {
                Console.Error.WriteLine("Decrypt usage: decrypt <validationKey> <decryptionKey> <encryptedTicket>");
                return 1;
            }

            string validationKey = args[1];
            string decryptionKey = args[2];
            string encryptedTicket = args[3];

            string tempConfig = null;
            AppDomain domain = null;

            try
            {
                tempConfig = WriteTempConfig(validationKey, decryptionKey, "HMACSHA256", "AES");
                domain = CreateChildDomainWithConfig(tempConfig);

                var worker = (FormsTicketWorker)domain.CreateInstanceFromAndUnwrap(
                    Assembly.GetExecutingAssembly().Location,
                    typeof(FormsTicketWorker).FullName);

                string result = worker.DecryptTicket(encryptedTicket);
                Console.WriteLine(result);
                return 0;
            }
            finally
            {
                if (domain != null)
                {
                    try { AppDomain.Unload(domain); } catch { /* ignore */ }
                }
                CleanupTempConfig(tempConfig);
            }
        }

        private static int HandleEncrypt(string[] args)
        {
            // encrypt <validationKey> <decryptionKey> <existingEncryptedTicket> <newUsernameOrDashToKeep> <minutes>
            if (args.Length < 6)
            {
                Console.Error.WriteLine("Encrypt usage: encrypt <validationKey> <decryptionKey> <existingEncryptedTicket> <newUsernameOrDashToKeep> <minutes>");
                return 1;
            }

            string validationKey = args[1];
            string decryptionKey = args[2];
            string existingEncryptedTicket = args[3];
            string newUser = args[4];
            if (!int.TryParse(args[5], out int minutes))
            {
                Console.Error.WriteLine("Invalid minutes: " + args[5]);
                return 1;
            }

            string tempConfig = null;
            AppDomain domain = null;

            try
            {
                tempConfig = WriteTempConfig(validationKey, decryptionKey, "HMACSHA256", "AES");
                domain = CreateChildDomainWithConfig(tempConfig);

                var worker = (FormsTicketWorker)domain.CreateInstanceFromAndUnwrap(
                    Assembly.GetExecutingAssembly().Location,
                    typeof(FormsTicketWorker).FullName);

                string encTicket = worker.ReEncryptTicket(existingEncryptedTicket, newUser, minutes);
                Console.WriteLine(worker.DecryptTicket(encTicket));
                Console.WriteLine(encTicket);
                return 0;
            }
            finally
            {
                if (domain != null)
                {
                    try { AppDomain.Unload(domain); } catch { /* ignore */ }
                }
                CleanupTempConfig(tempConfig);
            }
        }

        private static void PrintUsage()
        {
            Console.WriteLine("FormsTicketTool");
            Console.WriteLine();
            Console.WriteLine("Decrypt:");
            Console.WriteLine("  FormsTicketTool decrypt <validationKey> <decryptionKey> <encryptedTicket>");
            Console.WriteLine();
            Console.WriteLine("Encrypt (from existing ticket, optionally change username and expiry minutes):");
            Console.WriteLine("  FormsTicketTool encrypt <validationKey> <decryptionKey> <existingEncryptedTicket> <newUsernameOrDashToKeep> <minutes>");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  FormsTicketTool decrypt EBF9...  B26C...  <encTicket>");
            Console.WriteLine("  FormsTicketTool encrypt EBF9...  B26C...  <encTicket>  john  120");
            Console.WriteLine("  FormsTicketTool encrypt EBF9...  B26C...  <encTicket>  -    60   (keep original username)");
        }

        private static string WriteTempConfig(string validationKey, string decryptionKey, string validationAlg, string decryptionAlg)
        {
            // Create a temporary .config file for a child AppDomain to read machineKey from.
            string tempPath = Path.Combine(Path.GetTempPath(), "FormsTicketTool_" + Guid.NewGuid().ToString("N") + ".config");
            var sb = new StringBuilder();
            sb.AppendLine(@"<?xml version=""1.0"" encoding=""utf-8""?>");
            sb.AppendLine("<configuration>");
            sb.AppendLine("  <system.web>");
            sb.AppendLine(@"    <compilation debug=""false"" targetFramework=""4.0"" />");
            sb.AppendLine($@"    <machineKey validationKey=""{validationKey}"" decryptionKey=""{decryptionKey}"" validation=""{validationAlg}"" decryption=""{decryptionAlg}"" />");
            sb.AppendLine("  </system.web>");
            sb.AppendLine("</configuration>");
            File.WriteAllText(tempPath, sb.ToString(), Encoding.UTF8);
            return tempPath;
        }

        private static AppDomain CreateChildDomainWithConfig(string configPath)
        {
            var setup = new AppDomainSetup
            {
                ApplicationBase = AppDomain.CurrentDomain.SetupInformation.ApplicationBase,
                PrivateBinPath = AppDomain.CurrentDomain.SetupInformation.PrivateBinPath,
                ConfigurationFile = configPath
            };
            return AppDomain.CreateDomain("FormsTicketToolDomain", null, setup);
        }

        private static void CleanupTempConfig(string path)
        {
            try
            {
                if (!string.IsNullOrEmpty(path) && File.Exists(path))
                    File.Delete(path);
            }
            catch { /* ignore */ }
        }
    }

    // Runs inside the child AppDomain so System.Web reads the generated config (machineKey).
    public class FormsTicketWorker : MarshalByRefObject
    {
        public string DecryptTicket(string encryptedTicket)
        {
            var t = FormsAuthentication.Decrypt(encryptedTicket);
            if (t == null)
                return "Failed to decrypt ticket (result was null). Check keys, algorithms, and input.";

            var sb = new StringBuilder();
            sb.AppendLine("=====================");
            sb.AppendLine("Version: " + t.Version);
            sb.AppendLine("Name: " + t.Name);
            sb.AppendLine("IssueDate: " + t.IssueDate.ToString("o"));
            sb.AppendLine("Expiration: " + t.Expiration.ToString("o"));
            sb.AppendLine("IsPersistent: " + t.IsPersistent);
            sb.AppendLine("UserData: " + (t.UserData ?? ""));
            sb.AppendLine("CookiePath: " + t.CookiePath);
            sb.AppendLine("=====================");
            return sb.ToString();
        }

        public string ReEncryptTicket(string existingEncryptedTicket, string newUserOrDash, int minutes)
        {
            var original = FormsAuthentication.Decrypt(existingEncryptedTicket);
            if (original == null)
                throw new InvalidOperationException("Failed to decrypt existing ticket. Check keys/algorithms.");

            string user = newUserOrDash == "-" ? original.Name : newUserOrDash;

            var newTicket = new FormsAuthenticationTicket(
                1,
                user,
                DateTime.Now,
                DateTime.Now.AddMinutes(minutes),
                original.IsPersistent,
                original.UserData,
                original.CookiePath ?? "/"
            );

            string encrypted = FormsAuthentication.Encrypt(newTicket);
            if (string.IsNullOrEmpty(encrypted))
                throw new InvalidOperationException("Failed to encrypt the new ticket.");

            return encrypted;
        }
    }
}