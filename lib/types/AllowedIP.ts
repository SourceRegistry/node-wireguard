/**
 * An allowed IP range in CIDR notation, e.g. "10.0.0.2/32" or "fd00::/64".
 * 0.0.0.0/0 / ::/0 allow all IPv4 / IPv6 traffic, matching wgtypes.AllowedIPs.
 */
export type AllowedIP = string;
