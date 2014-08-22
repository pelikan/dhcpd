dhcpd
=====

Dynamic Host Configuration Protocol for IPv4 (DHCPv4) server daemon.

The main driving force behind this was OpenBSD's Google Summer of Code 2014.

Tested on OpenBSD/amd64 and OpenBSD/sparc64 both directly and through
a relay agent (HP A5800 Switch) with a variety of clients:

- Windows XP, 7, Phone
- dhcpcd 5.5.6 on Android
- dhcpcd 6.4.2 on Linux
- udhcpc 1.14.3 on Samsung TV
- udhcpc 1.11.2 on Ubiquiti airOS 5.5
- udhcpc 0.9.9 on Ubiquiti airOS 4.0
- OpenBSD dhclient
- Intel UNDI Boot Agent PXE-2.0, 2.1
- iPXE 1.0.0+ (09c5) inside QEMU 2.0.0
- Cisco IP Phone 7941 (requires DHCP option 150 to be faked)
- RouterBOOT on a big-endian MIPS board
- Xerox WorkCentre 3220
- dhcdrop http://www.netpatch.ru/devel/dhcdrop/
- sdhcp http://galos.no-ip.org/sdhcp
- Sony PlayStation 3
- Pioneer VSX-921K
- TP-link TL-WR841N
- TP-link TL-WR741N (makes 6 DHCPDISCOVERs before SELECTING)
- some Belkin router ([without the backdoor](https://github.com/elvanderb/TCP-32764)) (gets a lease, then releases it, then re-discovers asking for the same one, all with xid 0x1)
- Sony Bravia TV (option 57 violates ([RFC 2132](http://tools.ietf.org/html/rfc2132)); they probably wanted to write 9216 (0x2400) bytes and copied the length (0x02) byte on the left, which makes it look like 548 (0x0224) bytes, which of course is illegal)

What we need now:
=================
- a proper configuration file parser (Grégoire Duchêne was working on that
  in another GSoC project) integrated into dhcpctl + the format documented
- maybe transaction support will be needed to keep the reload process sane
- DHCPNAK can send Messages in plain text.  It isn't just about adding the
  const char *, I need fresh perspective on how NAKs currently work.  Will
  definitely happen after the code has been running for a while, and I had
  some time off the code base.
- Respect Max Message Size option.  Will happen after a while.
- Support other operating systems.  I have working code for Windows + Linux
  but need to put it all together.  My previous DHCP server manipulated ARP
  instead of sending stuff on BPF.  Then it's valgrind time :-)
- DHCPv6 support.  We need to understand the bloody RFC and support a small
  subset.  Certainly no rush at any cost.  RFC 4361 will be required as the
  identifiers seem to make sense between address families (and not just for
  tracking stolen laptops).
- Lease on-disk-dumper and multicast-syncer.  I was sort of hoping it would
  be a separate process, but we'll see.  Likely to happen after the parser.
- Some address-liveness awareness code, most likely ICMP before DHCPOFFERs.
  Maybe ARP snooping over dynamic ranges?  Would require another 2MB bitmap.
