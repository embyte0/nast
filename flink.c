/*
    NAST

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

/* return -1 on error, else 0 */

#include "include/nast.h"

int flink (u_char *dev)
{
   libnet_t *l = NULL;
   pcap_t   *p = NULL;

   u_short ether_type;
   struct libnet_icmpv4_hdr *icmp;
   struct libnet_ether_addr *mymac;
   struct host * uphost;
   libnet_ptag_t ptag;

   u_long myip;
   struct libnet_ipv4_hdr * ip;

   u_char errbuf[LIBNET_ERRBUF_SIZE];

   /*to be implemented*/
   int lg;

   struct timeval tv;
   fd_set rfsd;

   u_char testip[20]; /* ipsorci ritornati da map.c*/
   u_char mac_src[6], mac_dst[6]; /* mac address */
   u_long ip_src, ip_dst; /* ip da usare dopo */

   u_short i, k, sd, pcount, n; /* n=num of up hosts */

   i = n = k = ptag = ip_dst = sd = lg = 0;

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
	w_error (0,"Is very useless demonize me in finding link! Omit");
	demonize=0;
     }

   n_print ("princ",2,2,lg,"- Searching for possible hosts to use for test : waiting please... ");
   fflush (stdout);

   /* find two hosts for test */
   if ((uphost = map_lan(dev, 0, &n))==NULL)
     {
	if(w_error(0, "\nCan't build truly host list! mmhhh!\nReport bug to author please\n\n")==-1)
	  return(0);
     }

   /* there are at least 3 host in lan? */
   if (n<2)
     {
	n_print ("princ",4,2,lg,"\nYou have only %d host in lan, test won't be truly...\n", n+1);
	n_print ("princ",5,2,lg,"Try again with at least 3 hosts up.\n\n");
	return -1;
     }

   /* find a suitable host that reply to ping request */
   if ((l = libnet_init (LIBNET_RAW4, NULL, errbuf))==NULL)
     {
	w_error(1, "\nError : libnet_init: %s\n", errbuf);
     }

   if (!(mymac = libnet_get_hwaddr(l)))
     {
	w_error(1, "\nError : can't get hardware address: %s\n", libnet_geterror(l));
     }

   /* MAC is my MAC ADDRESS*/
   for (k=0; k<6; k++)
     mac_src[k]=mymac->ether_addr_octet[k];

   myip = libnet_get_ipaddr4(l);
   if (myip == -1)
     {
	w_error(1, "\nError : autodetect device ip address failed: %s\n", libnet_geterror(l));
     }

   if (libnet_build_icmpv4_echo(ICMP_ECHO, 0, 0, 1000, 5249, NULL, 0, l,0)==-1)
     {
        libnet_destroy(l);
	w_error(1, "\nError : can't build ICMP header : %s\n", libnet_geterror(l));
     }

   for (i = 0; i<n; i++)
     {
	sprintf(testip, "%d.%d.%d.%d", uphost[i].ip[0], uphost[i].ip[1], uphost[i].ip[2], uphost[i].ip[3]);
	if ( (ptag = libnet_build_ipv4(LIBNET_ICMPV4_ECHO_H + LIBNET_IPV4_H, 0x00, 1000, 0, 64, IPPROTO_ICMP, 0, myip, inet_addr(testip), NULL, 0, l, ptag)) ==-1)
	  {
	     libnet_destroy(l);
	     w_error(1, "\nError : can't build TCP header : %s\n", libnet_geterror(l));
	  }

	if (libnet_write (l) == -1)
	  {
	     libnet_destroy(l);
	     w_error(1, "\nError writing packet on wire : %s\n", libnet_geterror(l));

	  }

        /* open pcap device NOT in promisc mode */
	if ((p = pcap_open_live (dev, BUFSIZ, NOT_PROMISC, 10, errbuf))==NULL)
	  {
	     libnet_destroy(l);
	     w_error(1, "\nError : pcap_open_liver() error : %s\n", errbuf);
	  }

	/* retrive socket descriptor for select() funz */
	sd = pcap_fileno(p);

	/* timeout is 20 packet or timer.. */
	pcount = 1;

	/* try for an answer ... */
	for (;;)
	  {
	     if (pcount == 20) break;

             /* set 2 secondz delay | DONT TOUCH! */
	     FD_ZERO (&rfsd);
	     FD_SET (sd ,&rfsd);
	     tv.tv_sec = 2;
	     tv.tv_usec = 0;

	     if (!select(sd+1, &rfsd, NULL, NULL, &tv))
	       break;

	     /* capture packet (packet) and pcap_header (hdr) */
	     packet = (u_char *) pcap_next (p, &hdr);

	     if (packet==NULL) continue;
	     if ((ether_type = handle_ethernet (packet)) != ETHERTYPE_IP) continue;

	     if ((offset = (device(dev,p)))==-1) return -1;
	     ip = (struct libnet_ipv4_hdr *) (packet + offset);
	     icmp = (struct libnet_icmpv4_hdr *) (packet + offset + LIBNET_IPV4_H);

	     /* my destination victim hosts reply -> GOOD :-) */
	     if ((ip->ip_src.s_addr == inet_addr(testip)) && icmp->icmp_type==ICMP_ECHOREPLY && icmp->icmp_id == 1000)
	       {
		  /* sisitemo ip/mac dst */
		  ip_dst = ip->ip_src.s_addr;
		  for (k=0; k<6; k++)
		    mac_dst[k]=uphost[i].mac[k];

		  /* sistemo ip src */
		  /* subito il primo host risponde ai ping */
		  if (!i)
		    sprintf(testip, "%d.%d.%d.%d", uphost[1].ip[0], uphost[1].ip[1], uphost[1].ip[2], uphost[1].ip[3]);
		  else
		    sprintf(testip, "%d.%d.%d.%d", uphost[0].ip[0], uphost[0].ip[1], uphost[0].ip[2], uphost[0].ip[3]);

		  if ( (ip_src=inet_addr(testip)) == -1)
		    {
		       if(w_error(0, "\nError : uphost[].ip is not a valid ip. Mhh strange, contact developer please\n")==-1)
			 return(0);
		    }

		  /* host found */
		  pcap_close (p);
		  goto rfound;
	       }

	     /* altro pacchetto ricevuto */
	     pcount ++;

	  }

	/* l'host non risponde all'icmp request, vado al prossimo */
	pcap_close (p);
     }

   n_print ("winfo",1,1,lg,"\n\nI don't find any host in you LAN which reply to an icmp request!\nI need at last one to resolve test. Try again later and adjust firewall if you can...\n\n");
   return -1;

   /* --------------------------------------------------------------------- */

   rfound:
   n_print ("princ",2,68,lg,"OK");

   if (uphost) free (uphost);


   n_print ("princ",3,2,lg,"\n- Try to send icmp spoofed request... \n");

   if ((l = libnet_init (LIBNET_LINK, dev, errbuf))==NULL)
     {
	w_error(1, "libnet_init: %s\n", errbuf);
     }

   /* costruisco il pacchetto */
   if (libnet_build_icmpv4_echo(ICMP_ECHO, 0, 0, 1000, 5249, NULL, 0, l,0)==-1)
     {
	libnet_destroy(l);
	w_error(1, "Can't build ICMP header : %s\n", libnet_geterror(l));
     }

   if (libnet_build_ipv4(LIBNET_ICMPV4_ECHO_H + LIBNET_IPV4_H, 0x00, 1000, 0, 64, IPPROTO_ICMP, 0, ip_src, ip_dst, NULL, 0, l, 0)==-1)
     {
	libnet_destroy(l);
	w_error(1, "Can't build TCP header : %s\n", libnet_geterror(l));
     }

   if (libnet_build_ethernet(mac_dst, mac_src, ETHERTYPE_IP, NULL, 0, l, 0)==-1)
     {
	libnet_destroy(l);
	w_error(1, "Can't build ethernet header : %s\n", libnet_geterror(l));
     }

   /* write packet */
   if (libnet_write (l) == -1)
     {
	libnet_destroy(l);
	w_error(1, "Error writing packet on wire : %s\n", libnet_geterror(l));
     }

   /* open pcap device in promisc mode */
   if ((p = pcap_open_live (dev, BUFSIZ, PROMISC, 10, errbuf))==NULL)
     {
	libnet_destroy(l);
	w_error(1, "pcap_open_liver() error : %s\n", errbuf);
     }

   /* recupero il descrittore per la select() */
   sd = pcap_fileno(p);

   n_print ("princ",4,2,lg,"- Waiting for a possible reply...\n");

   /* per il traffico alto metto un timeout di 30 pacchetti */
   pcount = 1;

   for (;;)
     {
	if (pcount == 60)
	  {
	     n_print ("princ",6,2,lg,"- No answer -> supposed SWITCH present\n");
	     break;
	  }

        /* set 2 secondz delay | DON'T TOUCH! */
	FD_ZERO (&rfsd);
	FD_SET (sd ,&rfsd);
	tv.tv_sec = 2;
	tv.tv_usec = 0;

	if (!select(sd+1, &rfsd, NULL, NULL, &tv))
	  {
	     n_print("princ",6,2,lg,"- No answer within two seconds -> supposed SWITCH present\n");
	     break;
	  }

	/* capture packet (packet) and pcap_header (hdr) */
	packet = (u_char *) pcap_next (p, &hdr);
	if (packet==NULL)
	  {
	     //fprintf (stderr, "Null packet!\n");
	     break;
	  }

	if ((ether_type = handle_ethernet (packet)) != ETHERTYPE_IP) continue;

	offset = (device(dev,p));
	ip = (struct libnet_ipv4_hdr *) (packet + offset);
	icmp = (struct libnet_icmpv4_hdr *) (packet + offset + LIBNET_IPV4_H);

	if ((ip->ip_src.s_addr == ip_dst) && icmp->icmp_type==ICMP_ECHOREPLY && icmp->icmp_id
	    == 1000)
	  {
	     n_print ("princ",6,2,lg,"- Supposed HUB present\n");
	     break;
	  }

	/* altro pacchetto ricevuto */
	pcount ++;
     }
     
   if(graph)
   	n_print("winfo",2,1,0,"Finished\n");

   libnet_destroy(l);

   return 0;
}

