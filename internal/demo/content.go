package demo

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"time"
)

// jail is one of the demo's jails: how often it bans, for how long, and what a failure in its
// log looks like.
type jail struct {
	name    string
	file    string
	filter  string
	log     string
	perDay  float64
	banTime int64
	line    func(t time.Time, ip string, r *rand.Rand) string
}

var users = []string{"admin", "root", "test", "user", "oracle", "postgres", "ubuntu", "git", "deploy", "info"}
var probes = []string{"/wp-login.php", "/wp-admin/setup-config.php", "/.git/config", "/phpmyadmin/index.php",
	"/administrator/index.php", "/admin.php", "/.svn/entries", "/wp-admin/install.php"}

func jails(logs string) []jail {
	return []jail{
		{
			name: "scanners", file: "scanners.local", filter: "caddy-scanners", log: logs + "/caddy.log",
			perDay: 14, banTime: 86400,
			line: func(t time.Time, ip string, r *rand.Rand) string {
				return fmt.Sprintf(`{"level":"info","ts":%d.%03d,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"%s","proto":"HTTP/1.1","method":"GET","host":"shop.example.com","uri":"%s"},"status":404}`,
					t.Unix(), r.IntN(1000), ip, probes[r.IntN(len(probes))])
			},
		},
		{
			name: "sshd", file: "sshd.local", filter: "sshd", log: logs + "/auth.log",
			perDay: 9, banTime: 3600,
			line: func(t time.Time, ip string, r *rand.Rand) string {
				return fmt.Sprintf("%s host sshd[%d]: Failed password for invalid user %s from %s port %d ssh2",
					t.Format(time.Stamp), 1000+r.IntN(60000), users[r.IntN(len(users))], ip, 30000+r.IntN(30000))
			},
		},
		{
			name: "mailio", file: "mailio.local", filter: "mailio", log: logs + "/mailio.log",
			perDay: 5, banTime: 86400,
			line: func(t time.Time, ip string, r *rand.Rand) string {
				via := []string{"imap", "submission", "smtps", "admin"}[r.IntN(4)]
				return fmt.Sprintf(`{"time":"%s","level":"WARN","msg":"password refused","ip":"%s","via":"%s"}`,
					t.Format(time.RFC3339Nano), ip, via)
			},
		},
		{
			name: "nextcloud", file: "nextcloud.local", filter: "nextcloud", log: logs + "/nextcloud.log",
			perDay: 1.2, banTime: 86400,
			line: func(t time.Time, ip string, r *rand.Rand) string {
				return fmt.Sprintf(`{"reqId":"%08x","level":2,"time":"%s","remoteAddr":"%s","user":"--","app":"core","method":"POST","url":"/login","message":"Login failed: '%s' (Remote IP: '%s')"}`,
					r.Uint32(), t.Format(time.RFC3339), ip, users[r.IntN(len(users))], ip)
			},
		},
		{
			name: "gitea", file: "gitea.local", filter: "gitea", log: logs + "/gitea.log",
			perDay: 0.4, banTime: 14400,
			line: func(t time.Time, ip string, r *rand.Rand) string {
				return fmt.Sprintf("%s ...rs/web/auth/auth.go:%d:SignInPost() [I] Failed authentication attempt for %s from %s:%d: user does not exist",
					t.Format("2006/01/02 15:04:05"), 200+r.IntN(40), users[r.IntN(len(users))], ip, 30000+r.IntN(30000))
			},
		},
		{
			name: "f2b", file: "f2b.local", filter: "f2b", log: logs + "/f2b-web.log",
			perDay: 0.15, banTime: 86400,
			line: func(t time.Time, ip string, r *rand.Rand) string {
				return fmt.Sprintf(`{"time":"%s","level":"WARN","msg":"password refused","ip":"%s"}`, t.Format(time.RFC3339Nano), ip)
			},
		},
	}
}

// configFiles are the edited configuration the demo starts with.
func configFiles(logs string) map[string]string {
	return map[string]string{
		"settings/fail2ban.local": `# fail2ban's own settings. f2b keeps 90 days of bans unless dbpurgeage says otherwise.
[DEFAULT]
loglevel = INFO
dbpurgeage = 90d
`,
		"jails/defaults.local": `# What every jail does unless it says otherwise.
[DEFAULT]
# Never ban the host itself, or the office.
ignoreip  = 127.0.0.1/8 ::1 198.51.100.10
bantime   = 1d
findtime  = 10m
maxretry  = 5
# Published containers' traffic passes DOCKER-USER, not INPUT, and HTTP/3 comes over UDP.
# Keys of the jail: chain=… in banaction's brackets is overridden.
banaction = iptables-allports
chain     = DOCKER-USER
protocol  = all
`,
		"jails/sshd.local": `[sshd]
enabled   = true
mode      = aggressive
port      = ssh
logpath   = ` + logs + `/auth.log
# sshd is the host's, not a container's.
chain     = INPUT
bantime   = 1h
`,
		"jails/scanners.local": `# Anything asking for WordPress, phpMyAdmin or a .git directory.
[scanners]
enabled  = true
filter   = caddy-scanners
logpath  = ` + logs + `/caddy.log
maxretry = 3
`,
		"jails/mailio.local": `[mailio]
enabled  = true
filter   = mailio
logpath  = ` + logs + `/mailio.log
`,
		"jails/nextcloud.local": `[nextcloud]
enabled  = true
filter   = nextcloud
logpath  = ` + logs + `/nextcloud.log
maxretry = 3
`,
		"jails/gitea.local": `[gitea]
enabled  = true
filter   = gitea
logpath  = ` + logs + `/gitea.log
maxretry = 3
bantime  = 4h
findtime = 4h
`,
		"jails/f2b.local": `# Wrong passwords at this interface.
[f2b]
enabled  = true
filter   = f2b
logpath  = ` + logs + `/f2b-web.log
maxretry = 5
`,
		"filters/caddy-scanners.local": `# Caddy's JSON access log: requests for well-known administrative paths.
[Definition]

dirs  = (wp-admin|phpmyadmin|phpMyAdmin|administrator)\/
files = (wp-login\.php|admin\.php)
cvs   = \/\.(git|svn|bzr|hq)\/

failregex = ^{.*"remote_ip":"<HOST>".*"uri":"[^"]*\/(?:%(dirs)s|%(files)s)[^"]*"
            ^{.*"remote_ip":"<HOST>".*"uri":"[^"]*%(cvs)s[^"]*"

ignoreregex =
`,
		"filters/mailio.local": `[Definition]
failregex = ^\{.*"msg":"password refused".*"ip":"<ADDR>"
ignoreregex =
`,
		"filters/nextcloud.local": `# Nextcloud's refused sign-ins, from its JSON log.
[Definition]
failregex = ^.*"remoteAddr":"<HOST>".*"message":"Login failed:
ignoreregex =
`,
		"filters/gitea.local": `# Gitea's refused sign-ins.
[Definition]
failregex = ^.*Failed authentication attempt for .* from <ADDR>:\d+:
ignoreregex =
`,
		"filters/f2b.local": `[Definition]
failregex = ^\{.*"msg":"password refused".*"ip":"<ADDR>"
ignoreregex =
`,
	}
}

// stock stands in for fail2ban's own configuration, which the demo's image does not carry: a few
// files shaped like the real ones, written for the demo.
var stock = map[string]string{
	"jail.conf": `# The demo's stand-in for fail2ban's jail.conf, which in the engine image is the package's own.
[INCLUDES]
before = paths-debian.conf

[DEFAULT]
ignoreip =
bantime  = 10m
findtime = 10m
maxretry = 5
backend  = auto
banaction = iptables-multiport
banaction_allports = iptables-allports
filter   = %(__name__)s[mode=%(mode)s]
`,
	"paths-debian.conf": `# The demo's stand-in for fail2ban's paths-debian.conf.
[DEFAULT]
syslog_authpriv = /var/log/auth.log
sshd_log = %(syslog_authpriv)s
`,
	"fail2ban.conf": `# The demo's stand-in for fail2ban's fail2ban.conf.
[DEFAULT]
loglevel = INFO
logtarget = /var/log/fail2ban.log
dbpurgeage = 1d
`,
	"filter.d/sshd.conf": `# The demo's stand-in for fail2ban's sshd filter, which is much longer and knows every way
# sshd says no.
[INCLUDES]
before = common.conf

[Definition]
_daemon = sshd
failregex = ^.*Failed (?:password|publickey) for (?:invalid user )?\S+ from <HOST> port \d+
            ^.*Invalid user \S+ from <HOST>
ignoreregex =
`,
	"filter.d/common.conf": `# The demo's stand-in for fail2ban's common.conf, the prefixes most filters share.
[Definition]
__prefix_line = \s*
`,
	"action.d/iptables-allports.conf": `# The demo's stand-in for fail2ban's iptables-allports action.
[Definition]
actionstart = <iptables> -N f2b-<name>
actionban   = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>
`,
	"action.d/iptables-multiport.conf": `# The demo's stand-in for fail2ban's iptables-multiport action.
[Definition]
actionstart = <iptables> -N f2b-<name>
actionban   = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>
`,
}

// background is a line in a log that is not a failure, so a tester run over it misses some.
func background(j jail, t time.Time, r *rand.Rand) string {
	ip := fmt.Sprintf("198.51.100.%d", 20+r.IntN(200))
	switch j.name {
	case "scanners":
		paths := []string{"/", "/products", "/cart", "/favicon.ico", "/assets/app.js", "/about"}
		return fmt.Sprintf(`{"level":"info","ts":%d.%03d,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"%s","proto":"HTTP/2.0","method":"GET","host":"shop.example.com","uri":"%s"},"status":200}`,
			t.Unix(), r.IntN(1000), ip, paths[r.IntN(len(paths))])
	case "sshd":
		return fmt.Sprintf("%s host sshd[%d]: Accepted publickey for deploy from %s port %d ssh2",
			t.Format(time.Stamp), 1000+r.IntN(60000), ip, 30000+r.IntN(30000))
	case "mailio":
		return fmt.Sprintf(`{"time":"%s","level":"INFO","msg":"message delivered","account":"ac_01JD0000000000000000000000"}`, t.Format(time.RFC3339Nano))
	case "nextcloud":
		return fmt.Sprintf(`{"reqId":"%08x","level":1,"time":"%s","remoteAddr":"%s","user":"alice","app":"files","method":"PROPFIND","url":"/remote.php/dav/files/alice/","message":"Sync finished"}`, r.Uint32(), t.Format(time.RFC3339), ip)
	case "gitea":
		return fmt.Sprintf("%s ...ers/web/repo/view.go:%d:Home() [I] Request finished for %s: 200 OK", t.Format("2006/01/02 15:04:05"), 100+r.IntN(40), ip)
	default:
		return fmt.Sprintf(`{"time":"%s","level":"INFO","msg":"signed in","ip":"%s"}`, t.Format(time.RFC3339Nano), ip)
	}
}

// address picks who did it: mostly from a crowd, often from a few regulars, which is what makes
// repeat offenders.
func address(r *rand.Rand) string {
	if r.IntN(4) == 0 {
		regulars := []string{"203.0.113.7", "203.0.113.45", "192.0.2.19", "203.0.113.200", "192.0.2.88", "2001:db8:5::17"}
		return regulars[r.IntN(len(regulars))]
	}
	if r.IntN(12) == 0 {
		return fmt.Sprintf("2001:db8:%x::%x", r.IntN(0xffff), r.IntN(0xffff))
	}
	nets := []string{"192.0.2", "203.0.113"}
	return fmt.Sprintf("%s.%d", nets[r.IntN(2)], 1+r.IntN(254))
}

func fail2banLine(t time.Time, logger, level, msg string) string {
	return fmt.Sprintf("%s %-24s[1]: %-8s %s", t.UTC().Format("2006-01-02 15:04:05,000"), logger, level, msg)
}

func jailNote(j string, msg string) string {
	return strings.TrimSpace(fmt.Sprintf("[%s] %s", j, msg))
}
