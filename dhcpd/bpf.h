/*
 * Copyright (c) 2014 Martin Pelikan <pelikan@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#pragma once
#include <net/bpf.h>

/*
 * BPF filters can be compiled using libraries such as libpcap.  tcpdump -d
 * will print out many forms, neither of which is as descriptive as this one.  
 *
 * We're only interested in reading 'ip and udp and dst port bootps'.
 */
struct bpf_insn dhcp_bpf_rfilter[] = {
	/* IPv4 in ethertype. */
 /*00*/	BPF_STMT(BPF_LD	| BPF_H | BPF_ABS,	12),
 /*01*/	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,	ETHERTYPE_IP,	0, 8),

	/* UDP in IP next header. */
 /*02*/	BPF_STMT(BPF_LD	| BPF_B | BPF_ABS,	23),
 /*03*/	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,	IPPROTO_UDP,	0, 6),

	/* Drop it if it is a fragment. */
 /*04*/	BPF_STMT(BPF_LD	| BPF_H | BPF_ABS,	20),
 /*05*/	BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K,	0x1FFF,		4, 0),

	/* IPv4 header length into the accumulator using the dirty MSH. */
 /*06*/	BPF_STMT(BPF_LDX | BPF_B | BPF_MSH,	14),

	/* Based on the header length, locate the UDP destination port. */
 /*07*/	BPF_STMT(BPF_LD	| BPF_H | BPF_IND,	16),
 /*08*/	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,	BOOTP_SERVER_PORT,	0, 1),

	/* Success -- give us the whole packet, but don't waste memory. */
 /*09*/	BPF_STMT(BPF_RET | BPF_K,	MTU),

	/* Failure -- drop the packet. */
 /*10*/	BPF_STMT(BPF_RET | BPF_K,	0),
};

/*
 * Allow the unprivileged daemon to write only packets according to:
 * 'ip and udp and src port bootps and dst port (bootps or bootpc)'
 */
struct bpf_insn dhcp_bpf_wfilter[] = {
	/* IPv4 in ethertype. */
 /*00*/	BPF_STMT(BPF_LD	| BPF_H | BPF_ABS,	12),
 /*01*/	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,	ETHERTYPE_IP,	0, 11),

	/* UDP in IP next header. */
 /*02*/	BPF_STMT(BPF_LD	| BPF_B | BPF_ABS,	23),
 /*03*/	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,	IPPROTO_UDP,	0, 9),

	/* Drop it if it is a fragment. */
 /*04*/	BPF_STMT(BPF_LD	| BPF_H | BPF_ABS,	20),
 /*05*/	BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K,	0x1FFF,		7, 0),

	/* IPv4 header length into the accumulator using the dirty MSH. */
 /*06*/	BPF_STMT(BPF_LDX | BPF_B | BPF_MSH,	14),

	/* Based on the header length, locate the UDP source port. */
 /*07*/	BPF_STMT(BPF_LD	| BPF_H | BPF_IND,	14),
 /*08*/	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,	BOOTP_SERVER_PORT,	0, 1),

	/* Based on the header length, locate the UDP destination port. */
 /*09*/	BPF_STMT(BPF_LD	| BPF_H | BPF_IND,	16),
 /*10*/	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,	BOOTP_CLIENT_PORT,	1, 0),
	/* RFC 1542: Delivering BOOTREPLY packets to relays use that port. */
 /*11*/	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,	BOOTP_SERVER_PORT,	0, 1),

	/* Success -- allow writing the whole packet to a reasonable limit. */
 /*12*/	BPF_STMT(BPF_RET | BPF_K,	MTU),

	/* Failure -- don't send this out! */
 /*13*/	BPF_STMT(BPF_RET | BPF_K,	0),
};
