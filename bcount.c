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

#include "include/nast.h"

#define Rst 0
#define Fin 1

int conn_len(u_long ip_src,u_long ip_dst,u_short s_port,u_short d_port, double len);

struct statistics
{
   unsigned long s_ip;
   unsigned long d_ip;
   unsigned short s_port;
   unsigned short d_port;
   double tot_len;
   int lin;
}
stat_conn[100];

void bytecounting ();
void n_bytecounting (); /*with graphic*/
int run_bc (char *dev, char *filter);
void ptimecounting();

int nconns = 0;
int liness = 13;

unsigned long ptime; /* parzial time of execution, in seconds */

double partial; /* partial traffic */
time_t begin; /* save begin time for calculate avarage rate */

int run_bc (char *dev, char *filter)
{
   char ebuf[PCAP_ERRBUF_SIZE];

   if (!dev)
     {
	w_error(1, "Device is null!\n");
     }
#ifdef HAVE_LIBNCURSES
   if (graph)
     init_scr();
#endif

   if (demonize)
     n_print ("winfo",1,1,0,"Is very useless demonize me in finding gateway! Omit");

   /* 1 to avoid inf */
   ptime=1;

   begin = time(NULL);

   /* open pcap sniffer */
   if ((pcap_lookupnet(dev, &netp, &maskp, ebuf))==-1)
     {
	w_error(1,"pcap_lookupnet error: %s\n\n", ebuf);
     }
   if ((descr = pcap_open_live(dev, BUFSIZ, PROMISC, 10, ebuf))==NULL)
     {
	w_error(1, "pcap_open_live error: %s\n\n", ebuf);
     }

   if ((offset=(device(dev,descr)))==-1) return -1;

   if (strcmp (filter, "any") && strcmp (filter, "")) /* filter!="any" */
     {

	if ((pcap_compile (descr, &fp, filter, 0, netp))==-1)
	  {
	     w_error(0, "pcap_compile error\n\n");
	     return 0;
	  }
	if ((pcap_setfilter (descr, &fp))==-1)
	  {
	     w_error(0, "pcap_setfilter error\n\n");
	     return 0;
	  }

	n_print ("princ",0,1,0,"Filter \"%s\" has been applied to \"%s\"\n\n", filter, dev);
     }
   else
     n_print ("princ",0,1,0,"Reading from \"%s\"\n\n", dev);

   pthread_create (&pt[0], NULL, (void *) ptimecounting, NULL);
   if(graph)
     pthread_create (&pt[1], NULL, (void *) n_bytecounting, NULL);
   else
     bytecounting() ;

   return 0;
}

void bytecounting ()
{
   u_short icons;
   double total;
   double pspeed, tspeed; /* current and total speed */
   unsigned long long number;
   char *units[] =
     {
	"B/s", "kB/s", "MB/s", "GB/s"
     };
   char value[15];
   int line;

   total=0;
   icons=0;
   number=0;
   partial=0;
   line = 4;

   n_print (NULL,0,0,0,"Packets\t\tTotal\t\tCurrent speed\t\tAvarage speed\n");
   n_print (NULL,0,0,0,"---------------------------------------------------------------------\n");

   while (1)
     {
	if ((packet = (u_char *) pcap_next (descr, &hdr))!=NULL)
	  {
	     total+=(double)(hdr.len)/1024; /* sum (Kbytes)*/
	     partial+=(double)(hdr.len)/1024;
	     ++number;

	     /* clean line */
	     printf ("\r                                                                     \r");

	     switch (icons)
	       {
		case 0: printf ("\\ "); break;
		case 1: printf ("| "); break;
		case 2: printf ("/ "); break;
		case 3: printf ("- "); break;
	       }
	     if (icons==3) icons=0;
	     else icons++;

             sprintf (value, "%Ld", number);
	     printf (value);

	     /* calculate space */
	     if (strlen(value) < 6) printf ("\t\t");
	     else printf ("\t");

	     if (total < 1)
	       sprintf (value, "%.0fB", total*1024);
	     else if (total < 1024)
	       sprintf (value, "%.2fkB", total);
	     else if (total < 1024*1024)
	       sprintf (value, "%.2fMB", total/1024);
	     else
	       sprintf (value, "%.2fGB", total/1024*1024);

	     printf ("%s", value);

	     /* calculate space */
	     if (strlen (value) < 8) printf ("\t\t");
	     else printf ("\t");

	     pspeed = partial/ptime;
	     if (pspeed < 1)
	       sprintf (value, "%.0f%s", pspeed*1024, units[0]);
	     else if (pspeed < 1024)
	       sprintf (value, "%.2f%s", pspeed, units[1]);
	     else if (pspeed < 1024*1024)
	       sprintf (value, "%.2f%s", pspeed/1024, units[2]);
	     else
	       sprintf (value, "%.2f%s", pspeed/1024*1024, units[3]);

	     printf ("%s", value);

	     /* calculate space */
	     if (strlen (value) < 7) printf ("\t\t\t");
	     else  if (strlen (value) < 13) printf ("\t\t");
	     else printf ("\t");

	     tspeed = total/((int)(time(NULL)-begin));
	     if (tspeed < 1)
	       sprintf (value, "%.0f%s", tspeed*1024, units[0]);
	     else if (tspeed < 1024)
	       sprintf (value, "%.2f%s", tspeed, units[1]);
	     else if (tspeed < 1024*1024)
	       sprintf (value, "%.2f%s", tspeed/1024, units[2]);
	     else
	       sprintf (value, "%.2f%s", tspeed/1024*1024, units[3]);

	     printf ("%s", value);
	     fflush (stdout);
	  }
     }

   pcap_close(descr);
}

void n_bytecounting()
{
   u_short icons;
   double total;
   double tot;
   double pspeed, tspeed; /* current and total speed */
   unsigned long long number;
   char *units[] =
     {
	"B/s", "kB/s", "MB/s", "GB/s"
     };
   char value[15];
   int line, l;
   int tcp,udp,icmp,igmp,arp,rarp,others;
   struct libnet_ipv4_hdr *ip;
   struct libnet_tcp_hdr *tcph;
   u_int16_t type;
   int k;

   total=tot=0;
   icons=0;
   number=0;
   partial=0;
   line = 4;
   l = 11;
   tcp = udp = icmp = igmp = others = arp = rarp = k = 0;

   for(k=0;k<100;k++)
     {
	memset(&stat_conn[k], 0, sizeof(stat_conn[k]));
     }

   n_print ("princ",1,1,0,"Packets\t\tTotal\t\tCurrent speed\t\tAvarage speed\n");
   n_print ("princ",2,1,0,"-----------------------------------------------------------------------------\n");
   n_print ("princ",6,1,0,"ARP        RARP        ICMP        IGMP         TCP        UDP        Others\n");
   n_print ("princ",7,1,0,"-----------------------------------------------------------------------------\n");
   n_print ("princ",11,1,0,"From             Port       To                  Port       Total traffic");
   n_print("princ",12,1,0,"-----------------------------------------------------------------------------\n");
   while(bc_glob!=0)
     {
	if ((packet = (u_char *) pcap_next (descr, &hdr))!=NULL)
	  {
	     total+=(double)(hdr.len)/1024; /* sum (Kbytes)*/
	     partial+=(double)(hdr.len)/1024;
	     ++number;
	     tot=(double)(hdr.len)/1024;

	     type = handle_ethernet (packet);

	     ip = (struct libnet_ipv4_hdr *) (packet+offset);
	     tcph = (struct libnet_tcp_hdr *) (packet + LIBNET_IPV4_H + offset);
	     switch(ip->ip_p)
	       {
		case IPPROTO_TCP:
		  ++tcp;
		  switch(tcph->th_flags)
		    {
		     case TH_SYN: 		
		       conn_len(ip->ip_src.s_addr,ip->ip_dst.s_addr,htons(tcph->th_sport),htons(tcph->th_dport),tot);
		       break;
		     case TH_ACK:     
		       conn_len(ip->ip_src.s_addr,ip->ip_dst.s_addr,htons(tcph->th_sport),htons(tcph->th_dport),tot);
		       break;
		     case TH_RST:
		       conn_len(ip->ip_src.s_addr,ip->ip_dst.s_addr,htons(tcph->th_sport),htons(tcph->th_dport),tot);
		       break;
		     case (TH_SYN|TH_ACK):
		       conn_len(ip->ip_src.s_addr,ip->ip_dst.s_addr,htons(tcph->th_sport),htons(tcph->th_dport),tot);
		       break;
		     case (TH_ACK|TH_PUSH):
		       conn_len(ip->ip_src.s_addr,ip->ip_dst.s_addr,htons(tcph->th_sport),htons(tcph->th_dport),tot);
		       break;
		     case (TH_URG|TH_ACK):
		       conn_len(ip->ip_src.s_addr,ip->ip_dst.s_addr,htons(tcph->th_sport),htons(tcph->th_dport),tot);
		       break;
		     case (TH_FIN|TH_ACK):
		       conn_len(ip->ip_src.s_addr,ip->ip_dst.s_addr,htons(tcph->th_sport),htons(tcph->th_dport),tot);
		       break;
		     case (TH_RST|TH_ACK):
		       conn_len(ip->ip_src.s_addr,ip->ip_dst.s_addr,htons(tcph->th_sport),htons(tcph->th_dport),tot);
		       break;
		     default:
		       break;
		    }

		  break;
		case IPPROTO_UDP:
		  ++udp;
		  break;
		case IPPROTO_ICMP:
		  ++icmp;
		  break;
		case IPPROTO_IGMP:
		  ++igmp;
		  break;
		default:
		  if (type==ETHERTYPE_ARP)
		    ++arp;
		  else if (type==ETHERTYPE_REVARP)
		    ++rarp;
		  else ++others;
		  break;
	       }
             n_print ("princ",8,1,0,"                                                                   ");
             n_print ("princ",8,3,0,"%d",arp);
	     n_print ("princ",8,15,0,"%d",rarp);
	     n_print ("princ",8,27,0,"%d",icmp);
	     n_print ("princ",8,39,0,"%d",igmp);
	     n_print ("princ",8,51,0,"%d",tcp);
	     n_print ("princ",8,63,0,"%d",udp);
	     n_print ("princ",8,75,0,"%d",others);

	     switch (icons)
	       {
		case 0: n_print ("princ",3,1,0,"\\ "); break;
		case 1: n_print ("princ",3,1,0,"| "); break;
		case 2: n_print ("princ",3,1,0,"/ "); break;
		case 3: n_print ("princ",3,1,0,"- "); break;
	       }
	     if (icons==3) icons=0;
	     else icons++;
	     
             n_print ("princ",3,1,0,"                                                                   ");
             sprintf (value, "%Ld", number);
	     n_print ("princ",3,3,0,"%s",value);

	     if (total < 1)
	       sprintf (value, "%.0fB", total*1024);
	     else if (total < 1024)
	       sprintf (value, "%.2fkB", total);
	     else if (total < 1024*1024)
	       sprintf (value, "%.2fMB", total/1024);
	     else
	       sprintf (value, "%.2fGB", total/1024*1024);

	     n_print ("princ",3,24,0,"%s",value);

	     pspeed = partial/ptime;
	     if (pspeed < 1)
	       sprintf (value, "%.0f%s", pspeed*1024, units[0]);
	     else if (pspeed < 1024)
	       sprintf (value, "%.2f%s", pspeed, units[1]);
	     else if (pspeed < 1024*1024)
	       sprintf (value, "%.2f%s", pspeed/1024, units[2]);
	     else
	       sprintf (value, "%.2f%s", pspeed/1024*1024, units[3]);

	     n_print ("princ",3,40,0,"%s",value);

	     tspeed = total/((int)(time(NULL)-begin));
	     if (tspeed < 1)
	       sprintf (value, "%.0f%s", tspeed*1024, units[0]);
	     else if (tspeed < 1024)
	       sprintf (value, "%.2f%s", tspeed, units[1]);
	     else if (tspeed < 1024*1024)
	       sprintf (value, "%.2f%s", tspeed/1024, units[2]);
	     else
	       sprintf (value, "%.2f%s", tspeed/1024*1024, units[3]);

	     n_print ("princ",3,64,0,"%s",value);
	  }
     }

   pcap_close(descr);
}

int conn_len(u_long ip_src,u_long ip_dst,u_short s_port,u_short d_port, double len)
{
   int i;
   char value[15];
   for(i=0;i<100;i++)
     if((ip_src==stat_conn[i].s_ip && ip_dst==stat_conn[i].d_ip && s_port==stat_conn[i].s_port && d_port==stat_conn[i].d_port) || (ip_src==stat_conn[i].d_ip && ip_dst==stat_conn[i].s_ip && s_port==stat_conn[i].d_port && d_port==stat_conn[i].s_port))
       {
	  stat_conn[i].tot_len += len;
	  if (stat_conn[i].tot_len < 1)
	    sprintf (value, "%.0fB", stat_conn[i].tot_len*1024);
	  else if (stat_conn[i].tot_len < 1024)
	    sprintf (value, "%.2fkB", stat_conn[i].tot_len);
	  else if (stat_conn[i].tot_len < 1024*1024)
	    sprintf (value, "%.2fMB", stat_conn[i].tot_len/1024);
	  else
	    sprintf (value, "%.2fGB", stat_conn[i].tot_len/1024*1024);
	  n_print("princ",stat_conn[i].lin,60,0,"%s",value);
	  return(0); /*ce l'ho gi�(duplicato)*/
       }

   for(i=0;i<100;i++)/*cerco spazio vuoto*/
     {
	if(stat_conn[i].s_ip)continue;
	else
	  {
	     stat_conn[i].s_ip = ip_src;
	     stat_conn[i].d_ip = ip_dst;
	     stat_conn[i].s_port = s_port;
	     stat_conn[i].d_port = d_port;
	     stat_conn[i].tot_len = len;

	     n_print("princ",liness,1,0,"%s",libnet_addr2name4(stat_conn[i].s_ip, LIBNET_DONT_RESOLVE));
	     n_print("princ",liness,18,0,"%d",stat_conn[i].s_port);
	     n_print("princ",liness,29,0,"%s",libnet_addr2name4(stat_conn[i].d_ip, LIBNET_DONT_RESOLVE));
	     n_print("princ",liness,49,0,"%d",stat_conn[i].d_port);

	     if (stat_conn[i].tot_len < 1)
	       sprintf (value, "%.0fB", stat_conn[i].tot_len*1024);
	     else if (stat_conn[i].tot_len < 1024)
	       sprintf (value, "%.2fkB", stat_conn[i].tot_len);
	     else if (stat_conn[i].tot_len < 1024*1024)
	       sprintf (value, "%.2fMB", stat_conn[i].tot_len/1024);
	     else
	       sprintf (value, "%.2fGB", stat_conn[i].tot_len/1024*1024);
	     n_print("princ",stat_conn[i].lin,60,0,"%s",value);

	     stat_conn[i].lin=liness;
	     nconns++;
	     liness++;
	     return(1);
	  }
     }
   return(0);
}

void ptimecounting()
{
   for (;;)
     {
	sleep(1);
	if (ptime==10)
	  {
	     /* refresh every X seconds */
	     ptime=1;
	     partial=0;
	  }
	else
	  ptime++;
     }

}
