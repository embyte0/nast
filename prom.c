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

/* if ip_dst is 0 scan for all network NIC */

int psearch (char *dev, u_long ip_dst, u_short lg)
{
   u_char enet_dst[6] =
     {
	0xff, 0xff, 0, 0, 0, 0
     };
   u_char enet_src[6];
   u_long ip_src;
   char errbuf[256];
   int sd,ln;
   fd_set rfsd;
   struct timeval tv;
   libnet_t *l;
   struct libnet_ether_addr *e;
   struct nast_arp_hdr *arp;
   u_char *pkt;
   struct host *uphost=NULL;
   u_short pcount, i, k;
   u_char ip[16];

   k = i = 0;
   ln = 3;

   if (lg)
     {
	openfile();
	n_print (NULL,0,0,lg,"Logging to file... \n");
	fflush (stdout);
	n_print (NULL,0,0,lg,"NAST SNIFFER SCAN REPORT\n");
	n_print (NULL,0,0,lg,"Made on %s\n\n", timed);
     }

#ifdef HAVE_LIBNCURSES
   if (graph)
     init_scr();
#endif

/* demonize */
   if (demonize)
     {
	w_error(0,"Is very useless demonize me in checking sniffers! Omit");
	demonize=0;
     }
     

   n_print("pop",7,2,lg,"This check can have false response, pay attention!\n");

   if ((l = libnet_init (LIBNET_LINK, dev, errbuf))==NULL)
     {
        w_error(1, "libnet_init: %s\n\n", errbuf);
     }

   if ((e = libnet_get_hwaddr(l))==NULL)
     {
	w_error(1, "Can't get hardware address: %s\n\n", libnet_geterror(l));
     }

   memcpy (enet_src, e->ether_addr_octet, 6);

   if ((pcap_lookupnet(dev, &netp, &maskp, errbuf))==-1)
     {
	w_error(1, "pcap_lookupnet error: %s\n", errbuf);
     }

   if ((ip_src = libnet_get_ipaddr4(l))==-1)
     {
	w_error(1, "Can't get local ip address : %s\n\n", libnet_geterror(l));
     }

   /* log all packets */

   if (ip_dst==0)
     {
	n_print ("princ",1,1,lg,"Probe for hosts...");
	fflush (logd);
	if ((uphost = map_lan(dev, 0, &k))==NULL)
	  {
	     if(w_error(0, "\nCan't build truly host list! mmhhh!\nReport bug to author please\n\n")==-1)
	       return(0);
	  }
	if (k==0)
	  {
	     if(w_error(0, "\nWhat are you doing? You are alone in this network!\n\n")==-1)
	       return(0);
	  }
	n_print ("princ",1,20,lg,"done\n\n");
     }

   /* only 1 host */
   if (ip_dst!=0) 
   {
   k=1;
   n_print("princ",1,1,lg,"Scanning for sniffer the following host:\n");
   }

   while (i < k)
     {
	/* single host */
	if (ip_dst!=0)
	  {
	     if (libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, 6, 4, ARPOP_REQUEST,
				  enet_src, (u_char *)&ip_src, enet_dst, (u_char *)&ip_dst,
				  NULL, 0, l, 0)==-1)
	       {
		  w_error(1, "Can't build arp header : %s\n\n", libnet_geterror(l));
	       }
	  }
	/* all network */
	else
	  {
	     if (libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, 6, 4, ARPOP_REQUEST,
				  enet_src, (u_char *)&ip_src, enet_dst, uphost[i].ip,
				  NULL, 0, l, 0)==-1)
	       {
		  w_error(1, "Can't build arp header : %s\n\n", libnet_geterror(l));
	       }
	  }

	if (libnet_build_ethernet(enet_dst, enet_src, ETHERTYPE_ARP, NULL, 0, l, 0)==-1)
	  {
	     w_error(1, "Can't build arp header : %s\n\n", libnet_geterror(l));
	  }

        /* inizializzo e recupero il file descriptor per la select */
	if ((descr = pcap_open_live(dev, BUFSIZ, NOT_PROMISC, 10, errbuf))==NULL)
	  {
	     libnet_destroy(l);
	     w_error(1, "pcap_open_liver() error : %s\n\n", errbuf);
	  }

	if ((pcap_compile(descr,&fp,"arp",0,netp))==-1)
	  {
	     libnet_destroy(l);
	     w_error(1, "error: %s\n", pcap_geterr (descr));
	  }

	if ((pcap_setfilter(descr,&fp))==-1)
	  {
	     libnet_destroy(l);
	     w_error(1, "error: %s\n", pcap_geterr (descr));
	  }

	sd = pcap_fileno(descr);

	if (ip_dst!=0) n_print ("princ",ln,1,lg,"%s (%s)   --------->", libnet_addr2name4(ip_dst, LIBNET_DONT_RESOLVE), libnet_addr2name4(ip_dst, LIBNET_RESOLVE));
	else
	  {
	     sprintf (ip, "%d.%d.%d.%d", uphost[i].ip[0], uphost[i].ip[1], uphost[i].ip[2], uphost[i].ip[3]);
	     n_print ("princ",ln,1,lg,"%s (%s)   --------->", ip, libnet_addr2name4(inet_addr(ip), LIBNET_RESOLVE));
	  }
	fflush (logd);

        /* mando il pacchetto */
	if (libnet_write(l)==-1)
	  {
	     w_error(1, "Error sending arp request : %s\n\n", libnet_geterror(l));
	  }

	if ((offset=(device(dev,descr)))==-1) return -1;
	pcount=1;

	for (;;)
	  {
             /* inizializzo la select() */
	     FD_ZERO (&rfsd);
	     FD_SET (sd ,&rfsd);
	     tv.tv_sec = 3;
	     tv.tv_usec = 0;

	     if (!select(sd+1, &rfsd, NULL, NULL, &tv) || (pcount==10))
	       {
		  n_print ("princ",ln,45,lg," Not found\n");
		  break;
	       }

	     if ((pkt = (u_char *) pcap_next(descr, &hdr))!=NULL)
	       {
		  arp = (struct nast_arp_hdr *) (pkt+offset);

		  if (ntohs(arp->ar_op)==2)
		    {
		       n_print ("princ",ln,45,lg," Found!\n");
		       break;
		    }
	       }

	     pcount++;

	  }

	/* next host */
	if (descr) pcap_close(descr);
	i++;
	++ln;

     }

   if (l) libnet_destroy(l);
   if (lg)
     {
	n_print (NULL,0,0,lg,"\nFinished\n\n");
	fclose (logd);
     }
   else
     {
	n_print("winfo",1,1,lg,"                                                   ");
	n_print ("winfo",1,1,lg,"\nFinished\n\n");
     }
   return 0;
}
