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

#include "include/nast.h"

void handle_ICMP (u_short d, u_short x, FILE *output, FILE *ldd)
{
   struct libnet_ipv4_hdr *ip;
   struct libnet_icmpv4_hdr *icmp;
   u_short size_ip, size_icmp, size_buf;


   size_ip = LIBNET_IPV4_H;
   size_icmp = LIBNET_ICMPV4_H; /* base ICMP header lenght */
   size_buf = 0;

   ip = (struct libnet_ipv4_hdr *) (packet+offset);
   icmp = (struct libnet_icmpv4_hdr *) (packet+size_ip+offset);

   n_print("princ",line_s,row_s,lg,"\n---[ ICMP ]----------------------------------------------------------\n");
   n_print("princ",line_s=line_s+2,row_s,lg,"%s", inet_ntoa(ip->ip_src));
   n_print("princ",line_s,16,lg," -> ");
   n_print("princ",line_s,24,lg,"%s\n", inet_ntoa(ip->ip_dst));
   n_print("princ",++line_s,row_s,lg,"Version: %d\t", ip->ip_v);
   n_print("princ",line_s,20,lg,"Lenght: %d\t", ntohs(ip->ip_len));
   n_print("princ",line_s,35,lg,"TTL: %d\n", ip->ip_ttl);
   n_print("princ",++line_s,row_s,lg,"Type: ");

   row_s = 8;
   switch((icmp->icmp_type))
     {
      case 0:
	n_print("princ",line_s,row_s,lg,"Echo reply\n");
	size_icmp+=4;
	break;
      case 3:
	n_print("princ",line_s,row_s,lg,"Dest_unreach: ");
	size_icmp+=4;
	switch (icmp->icmp_code)
	  {
	   case 0:
	     n_print("princ",line_s,28,lg,"Network Unreachable\n");
	     break;
	   case 1:
	     n_print("princ",line_s,28,lg,"Host Unreachable\n");
	     break;
	   case 2:
	     n_print("princ",line_s,28,lg,"Protocol Unreachable\n");
	     break;
	   case 3:
	     n_print("princ",line_s,28,lg,"Port Unreachable\n");
	     break;
	   case 4:
	     n_print("princ",line_s,28,lg,"Fragmentation neded (DF)\n");
	     break;
	   case 5:
	     n_print("princ",line_s,28,lg,"Source route failed\n");
	     break;
	   case 6:
	     n_print("princ",line_s,28,lg,"Destination network unknown\n");
	     break;
	   case 7:
	     n_print("princ",line_s,28,lg,"Destination host unknown\n");
	     break;
	   case 8:
	     n_print("princ",line_s,28,lg,"Source host isolated\n");
	     break;
	   case 9:
	     n_print("princ",line_s,28,lg,"Destination network administratively prohibited\n");
	     break;
	   case 10:
	     n_print("princ",line_s,28,lg,"Destination host administratively prohibited\n");
	     break;
	   case 11:
	     n_print("princ",line_s,28,lg,"Network unreacjable(tOS)\n");
	     break;
	   case 12:
	     n_print("princ",line_s,28,lg,"Host Unreachable (tOS)\n");
	     break;
	   case 13:
	     n_print("princ",line_s,28,lg,"Communication administratively prohibited\n");
	     break;
	   case 14:
	     n_print("princ",line_s,28,lg,"Host precedence violation\n");
	     break;
	   case 15:
	     n_print("princ",line_s,28,lg,"Precedence cutoff in effect\n");
	     break;
	   default:
	     n_print("princ",line_s,28,lg,"Unknown - error?\n");
	     break;
	  }
	break;
      case 4:
	n_print("princ",line_s,row_s,lg,"Source quench\n");
	size_icmp+=4;
	break;
      case 5:
	n_print("princ",line_s,row_s,lg,"Redirect: ");
	size_icmp+=4;
	switch(icmp->icmp_code)
	  {
	   case 0:
	     n_print("princ",line_s,28,lg,"Redirect for network\n");
	     break;
	   case 1:
	     n_print("princ",line_s,28,lg, "Redirect for host\n");
	     break;
	   case 2:
	     n_print("princ",line_s,28,lg,"Redircet for tos & network\n");
	     break;
	   case 3:
	     n_print("princ",line_s,28,lg,"Redirect for tos & host\n");
	     break;
	   default:
	     n_print("princ",line_s,28,lg,"Unknown - error?\n");
	     break;
	  }
	break;
      case 8:
	n_print("princ",line_s,row_s,lg,"Echo request\n");
	size_icmp+=4;
	break;
      case 11:
	n_print("princ",line_s,row_s,lg,"Time exceeded: ");
	size_icmp+=4;
	switch (icmp->icmp_code)
	  {
	   case 0:
	     n_print("princ",line_s,28,lg,"TTL (0) during transit\n");
	     break;
	   case 1:
	     n_print("princ",line_s,28,lg,"TTL (0) during reassembly\n");
	     break;
	   default:
	     n_print("princ",line_s,28,lg,"Unknown - error?\n");
	     break;
	  }
	break;
      case 12:
	n_print("princ",line_s,row_s,lg,"Parameter problem: ");
	switch (icmp->icmp_code)
	  {
	   case 0:
	     n_print("princ",line_s,28,lg,"IP header bad\n");
	     break;
	   case 1:
	     n_print("princ",line_s,28,lg,"Requiring option missing\n");
	     break;
	  }
	break;
      case 13:
	n_print("princ",line_s,row_s,lg,"Timestamp\n");
	size_icmp+=16;
	break;
      case 14:
	n_print("princ",line_s,row_s,lg,"Timestamp reply\n");
	size_icmp+=16;
	break;
      case 15:
	n_print("princ",line_s,row_s,lg,"Information\n");
	break;
      case 16:
	n_print("princ",line_s,row_s,lg,"Information reply\n");
	break;
      case 17:
	n_print("princ",line_s,row_s,lg,"Address mask\n");
	size_icmp+=8;
	break;
      case 18:
	n_print("princ",line_s,row_s,lg,"Address mask reply\n");
	size_icmp+=8;
	break;
      default:
	n_print("princ",line_s,row_s,lg, "%i\n", icmp->icmp_type);
	break;
     }
     
   n_print("princ",++line_s,0,lg,"Packet Number: %d",npkt);

   if(!graph)
   	printf("\n");

   size_buf = ntohs(ip->ip_len) - size_ip - size_icmp;
   row_s=0;
   ++line_s;

   if (size_buf)
     {
	buf = (char *) (packet + size_ip + size_icmp + offset);

	if (d)
	  {
	     n_print("princ",line_s,row_s,lg,"\n---[ ICMP Data ]-----------------------------------------------------\n");
	     data_sniffo (buf, size_buf, output);
	     line_s+=2;
	  }

	if (x)
	  {
	     n_print("princ",line_s,row_s,lg,"\n---[ ICMP Hex-Ascii Data ]-------------------------------------------");
	     print_ascii_hex (buf, size_buf, output);
	     line_s+=2;
	  }

        /* log data (payload only) */
	if (ldd)
	  {
	     fprintf(ldd, "%s -> %s ICMP\n", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
	     data_sniffo (buf, size_buf, ldd);
	     fprintf(ldd, "\n");

	  }
     }
   row_s = 0;

}

