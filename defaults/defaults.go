// organize default config settings (less mess :3)
package defaults

// return all ports, sorted in order from the most commonly used to elast commonly used
func Ports() []int {
	ports := make([]int, len(VeryCommon)+len(CommonEnterprise)+len(ServiceSpecific)+len(Rare))

	ports = append(ports, VeryCommon...)
	ports = append(ports, CommonEnterprise...)
	ports = append(ports, ServiceSpecific...)
	ports = append(ports, Rare...)
	return ports
}

var VeryCommon = []int{
	80,  // HTTP
	443, // HTTPS
	22,  // SSH
	21,  // FTP
	25,  // SMTP
	110, // POP3
	143, // IMAP
	993, // IMAPS
	445, // SMB
	139, // NetBIOS/SMB legacy
}

var CommonEnterprise = []int{
	3389, // RDP
	3306, // MySQL
	1433, // MS SQL
	1521, // Oracle DB
	389,  // LDAP
	636,  // LDAPS
	8080, // HTTP-alt / Proxy
	5900, // VNC
}

var ServiceSpecific = []int{
	69,   // TFTP
	88,   // Kerberos
	111,  // RPCbind
	119,  // NNTP
	135,  // MS RPC endpoint mapper
	161,  // SNMP
	162,  // SNMP trap
	554,  // RTSP
	631,  // CUPS / IPP
	2049, // NFS
	2100, // Oracle XDB, etc.
	4445, // Misc / trojan history
	4555, // Misc / trojan history
}

var Rare = []int{
	23,    // Telnet
	199,   // SMUX
	1748,  // Enterprise middleware
	1754,  // Enterprise middleware
	1808,  // Enterprise middleware
	1809,  // Enterprise middleware
	3339,  // Misc / trojan
	47001, // Windows WMI mgmt
	5357,  // MS Web Services
	5722,  // MS RPC replication
	9389,  // Active Directory Web Services
	1025,  // Ephemeral / old services
}

var CommonEndpoints = []string{
	// auth & User
	"/login", "/signin", "/auth", "/session",
	"/register", "/signup", "/create-account",
	"/logout", "/signout",
	"/forgot-password", "/reset-password", "/password-reset", "/recover",
	"/profile", "/account", "/me", "/user", "/users",

	// API / Data
	"/api/", "/api/v1/", "/api/v2/", "/api/internal/",
	"/graphql", "/gql",
	"/swagger", "/swagger-ui", "/swagger.json", "/api-docs", "/openapi.json", "/redoc",
	"/ws", "/wss", "/socket.io/",

	// admin / management
	"/admin", "/administrator", "/admins", "/dashboard",
	"/manage", "/management", "/cms", "/console", "/controlpanel",
	"/settings", "/config", "/configs", "/configuration",

	// monitoring / debug
	"/status", "/status/health", "/status/ping",
	"/health", "/healthz", "/live", "/ready", "/readiness",
	"/metrics", "/telemetry", "/actuator", "/actuator/health", "/actuator/info",
	"/debug", "/debug/vars", "/debug/pprof/", "/trace", "/info", "/version", "/build",

	// static / informational
	"/robots.txt", "/sitemap.xml", "/crossdomain.xml",
	"/humans.txt", "/security.txt",
	"/server-status", "/server-info", "/whoami",

	// dev / test / backup
	"/test", "/testing", "/tests", "/qa", "/staging", "/uat",
	"/dev", "/development", "/old", "/backup", "/backups", "/bak", "/.old", "/.bak",
	"/archive", "/archives", "/logs", "/log", "/debug.log", "/error.log",
	"/tmp", "/temp",

	// source control / artifacts
	"/.git/", "/.git/config", "/.gitignore",
	"/.svn/", "/.hg/", "/.bzr/",
	"/.DS_Store", "/Thumbs.db",

	// common apps
	"/phpmyadmin", "/pma", "/myadmin",
	"/adminer", "/pgadmin", "/solr",
	"/kibana", "/grafana", "/jenkins", "/gitlab", "/gitlab/api",
	"/jira", "/confluence", "/redmine",

	// language specific
	"/phpinfo.php", "/server.php", "/info.php",
	"/config.php", "/localsettings.php", "/wp-config.php",
	"/index.php~", "/index.php.bak", "/index.old.php",

	// well known
	"/.well-known/", "/.well-known/security.txt", "/.well-known/change-password",
	"/.well-known/openid-configuration", "/.well-known/apple-app-site-association",

	// other interesting
	"/uploads", "/upload", "/files", "/downloads", "/download",
	"/static", "/assets", "/public", "/private",
	"/data", "/database", "/db", "/sql", "/dba",
	"/keys", "/secret", "/secrets", "/credentials",
	"/env", "/.env", "/environment", "/config.json",
}
