/*
    nast

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

*/

/* See RFC 826 for protocol description.  ARP packets are variable
   in size; the arphdr structure defines the fixed-length portion.
   Protocol type values are the same as those for 10 Mb/s Ethernet.
   It is followed by the variable-sized fields ar_sha, arp_spa,
   arp_tha and arp_tpa in that order, according to the lengths
   specified.  Field names used correspond to RFC 826.  */

struct nast_arp_hdr
{
   unsigned short int ar_hrd;		/* Format of hardware address.  */
   unsigned short int ar_pro;		/* Format of protocol address.  */
   unsigned char ar_hln;		/* Length of hardware address.  */
   unsigned char ar_pln;		/* Length of protocol address.  */
   unsigned short int ar_op;		/* ARP opcode (command).  */

   unsigned char __ar_sha[ETHER_ADDR_LEN];	/* Sender hardware address.  */
   unsigned char __ar_sip[4];		/* Sender IP address.  */
   unsigned char __ar_tha[ETHER_ADDR_LEN];	/* Target hardware address.  */
   unsigned char __ar_tip[4];		/* Target IP address.  */

   /* ARP protocol opcodes. */
   #define	ARPOP_REQUEST		1		/* ARP request.  */
   #define	ARPOP_REPLY		2		/* ARP reply.  */
   #define	ARPOP_RREQUEST		3		/* RARP request.  */
   #define	ARPOP_RREPLY		4		/* RARP reply.  */
   #define	ARPOP_InREQUEST		8		/* InARP request.  */
   #define	ARPOP_InREPLY		9		/* InARP reply.  */
   #define	ARPOP_NAK		10

};

