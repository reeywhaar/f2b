import type { Kind, Stock } from "@app/api/types";

const bare = (name: string) => name.replace(/\.(local|conf)$/, "");

/**
 * What a new file starts with: enough to show the shape, with nothing in it that fail2ban
 * would take as meant. A filter or an action named after a stock one starts as an override of
 * it, which changes only what it sets.
 */
export function templateFor(kind: Kind, name: string, stock?: Stock): string {
  const b = bare(name);
  switch (kind) {
    case "jails":
      return `[${b}]
enabled   = true
filter    = ${b}
logpath   = /remotelogs/docker/${b}.log
maxretry  = 5
findtime  = 10m
bantime   = 1d
# A published container's traffic passes DOCKER-USER, not INPUT, and HTTP/3 comes over UDP.
# Keys of the jail: chain=… in banaction's brackets is overridden.
banaction = iptables-allports
chain     = DOCKER-USER
protocol  = all
`;
    case "filters":
      if (stock?.filters.includes(`${b}.conf`)) {
        return `# Overrides filter.d/${b}.conf: only what is set here changes.
[Definition]
`;
      }
      return `[Definition]
# One regular expression a line. <ADDR> is the address; <HOST> is an address or a host name.
failregex = 
ignoreregex =
`;
    case "actions":
      if (stock?.actions.includes(`${b}.conf`)) {
        return `# Overrides action.d/${b}.conf: only what is set here changes.
[Definition]
`;
      }
      return `[Definition]
actionstart =
actionstop =
actioncheck =
# <ip> is the address being banned, <name> the jail.
actionban =
actionunban =
`;
    case "settings":
      if (name === "fail2ban.local") {
        return `[DEFAULT]
# CRITICAL, ERROR, WARNING, NOTICE, INFO or DEBUG.
loglevel = INFO
# How long fail2ban's database keeps bans, which is how far back the history goes.
dbpurgeage = 90d
`;
      }
      if (name === "jail.local") {
        return `[DEFAULT]
# Never banned: this host, and add your own.
ignoreip = 127.0.0.1/8 ::1
bantime  = 1d
findtime = 10m
maxretry = 5
`;
      }
      return `[DEFAULT]
# Where the stock jails look for logs, for one that reads somewhere else here.
# sshd_log = /var/log/auth.log
`;
  }
}

/**
 * A new jail with a filter, reading a log: what a new jail starts with, saying both. Without a
 * log, as for lines pasted, the template's stands for one.
 */
export function jailFor(name: string, filter: string, log?: string): string {
  const jail = templateFor("jails", name).replace(
    /^filter(\s*)= .*$/m,
    (_, gap: string) => `filter${gap}= ${filter}`,
  );
  return log
    ? jail.replace(
        /^logpath(\s*)= .*$/m,
        (_, gap: string) => `logpath${gap}= ${log}`,
      )
    : jail;
}

/**
 * Content a new file was made from, handed to its editor across the navigation: a duplicate's,
 * or a jail made for a filter.
 * Kept until the file is saved, so the editor reading it twice, as React does while developing,
 * reads it the same both times. A reload of the page starts from the template instead.
 */
const seeds = new Map<string, string>();

const seedKey = (kind: Kind, name: string) => `${kind}/${name}`;

export function seed(kind: Kind, name: string, content: string) {
  seeds.set(seedKey(kind, name), content);
}

export function seeded(kind: Kind, name: string): string | undefined {
  return seeds.get(seedKey(kind, name));
}

export function unseed(kind: Kind, name: string) {
  seeds.delete(seedKey(kind, name));
}
