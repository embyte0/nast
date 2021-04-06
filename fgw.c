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

/* try to find lan-gateway
 *
 * return 1 if lan-gw is found
 * return 0 if lan-gw is not found
 * return -1 on error
 *
 */

 /* This version is limitated:
  * Max 255 hosts to search gateway for ...
  */

#include "include/nast.h"

int fgw (u_char *dev)
{
   /* an "external" ip (www.google.com) */
   u_char *extip =
     {
	"66.102.11.99"
     };
   u_long myip;
   struct libnet_ether_addr *tmpmac;
   u_char mymac[6];
   u_short i, k, pcount;
   u_short n; /* n=number of up hosts */
   int line,col;
   libnet_t *l;
   u_char ebuf[LIBNET_ERRBUF_SIZE];
   libnet_ptag_t ptag;

   /* to be implemented*/
   int lg;

   pcap_t *p;

   struct host * uphost;

   /* pcap options */
   u_int16_t type;
   struct libnet_ipv4_hdr *ip;
   struct libnet_tcp_hdr *tcp;
   int sd;

   struct timeval tv;
   fd_set rfsd;

   n = k = ptag = pcount = lg = 0;
   line = col = 1;

   /* query device to find MAC / IP / NETMASK */
   if (!dev)
     {
	w_error(1, "Device is null!\n");
     }
#ifdef HAVE_LIBNCURSES
   if (graph)
     init_scr();
#endif

   if (demonize) 
   {
     w_error(0, "Is very useless demonize me in finding gateway! Omit");
     demonize = 0;
   }
	
   l = libnet_init (LIBNET_LINK, dev, ebuf);
   myip = libnet_get_ipaddr4(l);
   tmpmac = libnet_get_hwaddr(l);
   for (i=0; i<6; i++) mymac[i]=tmpmac->ether_addr_octet[i];

   /* init libnet_t *l  */
   l = libnet_init (LIBNET_LINK, dev, ebuf);

   /* build tcp and ip header (this doesn't change */
   if (libnet_build_tcp (2500, 80, 847930886, 524972923, 0x02, 32767, 0, 0, LIBNET_TCP_H, NULL, 0, l, 0)==-1)
     {
	libnet_destroy (l);
	w_error(1, "Error building tcp header : %s\n" ,libnet_geterror(l));
     }

   if (libnet_build_ipv4 (LIBNET_TCP_H + LIBNET_IPV4_H, 0x08, 35320, 0, 64, IPPROTO_TCP, 0, myip, libnet_name2addr4(l, extip, LIBNET_DONT_RESOLVE), NULL, 0, l, 0)==-1)
     {
	libnet_destroy(l);
	w_error(1, "Error building ip header : %s\n", libnet_geterror(l));
     }

   n_print ("princ",line,col,lg,"Finding suitable hosts (excluding localhost) -> ");
   fflush (stdout);

   /* find up possible hosts */
   if ((uphost = map_lan(dev, 0, &n))==NULL)
     {
	if(w_error(0, "\nCan't build truly host list! mmhhh!\nReport bug to author please\n\n")==-1)
	  return -1;
     }
   if (n==0)
     {
	if(w_error(0,"What are you doing? You are alone in this network!\n\n")==-1)
	return -1;
     }

   n_print ("princ",line,50,lg,"Done\n\n");

   line = line+2;
   /* set gwip and increment within for cicle */
   while (k < n)
     {
	n_print ("princ",line,col,lg,"Trying %d.%d.%d.%d (%s)-> ",uphost[k].ip[0], uphost[k].ip[1], uphost[k].ip[2], uphost[k].ip[3], nast_hex_ntoa (uphost[k].mac));
	fflush (stdout);

	if ((ptag = libnet_build_ethernet (uphost[k].mac, mymac, 0x0800, NULL, 0, l, ptag))==-1)
	  {
	     libnet_destroy(l);
	     w_error(1, "Error rebuilding ethernet frame : %s\n", libnet_geterror(l));
	  }

	if (libnet_write (l) == -1)
	  {
	     libnet_destroy(l);
	     w_error(1, "Error writing packet on wire : %s\n", libnet_geterror(l));
	  }

	pcap_lookupnet(dev,&netp,&maskp,ebuf);

	if ((p = pcap_open_live (dev, BUFSIZ, NOT_PROMISC, 10, ebuf))==NULL)
	  {
	     libnet_destroy(l);
	     w_error(1, "pcap_open_live() error : %s\n", ebuf);
	  }

	/* to better work with many traffic */
	pcap_compile(p,&fp,"src port 80 and dst port 2500",0,netp);
	pcap_setfilter(p,&fp);

	sd = pcap_fileno(p);

	/* try to sniff */

	for (;;)
	  {

	     /* set 2 secondz delay | DONT TOUCH! */
	     FD_ZERO (&rfsd);
	     FD_SET (sd ,&rfsd);
	     tv.tv_sec = 2;
	     tv.tv_usec = 0;

	     /* 30 packet max for delay */
	     if (pcount == 30)
	       {
		  n_print ("princ",line,2,lg,"Bad (timeout due to high traffic to your host, try again later to make sure)\n");
		  break;
	       }

	     if (!select(sd+1, &rfsd, NULL, NULL, &tv))
	       {
		  n_print ("princ",line,50,lg,"Bad\n");
		  break;
	       }

	     /* capture packet (packet) and pcap_header (hdr) */
	     packet = (u_char *) pcap_next (p, &hdr);

	     if (packet==NULL)
	       {
		  //fprintf (stderr, "Null packet!\n");
		  break;
	       }

	     type = handle_ethernet (packet);

	     if (type==ETHERTYPE_IP)
	       {
		  ip = (struct libnet_ipv4_hdr *) (packet + offset);
		  tcp = (struct libnet_tcp_hdr *) (packet + offset + sizeof(struct libnet_ipv4_hdr));

		  /* verify packet : ports and source ip*/
		  if ((ntohs(tcp->th_sport)==80) && (ntohs(tcp->th_dport)==2500) && (!strcmp(inet_ntoa(ip->ip_src), extip)))
		    {
		       n_print ("princ",line,50,lg,"Yep!\n");
		       break;
		    }
	       }

	     pcount ++;
	  }

	pcap_close(p);
	pcount = 1;
	k++;
	++line;
     }

   if(!graph)
     printf("\n");
   n_print("winfo",2,1,lg,"                                                     ");
   n_print("winfo",2,2,lg,"\nFinished\n");

   if (l) libnet_destroy(l);

   //printf ("\n");

   return 0;
}

