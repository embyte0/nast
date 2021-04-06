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

#include "n_nast.h"

#ifdef HAVE_LIBNCURSES

# define Rst 0
# define Fin 1

int add(u_long ip_src,u_long ip_dst,u_short sport,u_short dport);
int del(u_long ip_src,u_long ip_dst,u_short sport,u_short dport, int flag);

int nconn = 0;
int lines = 1;

int z = 0;
int tmp;

int connection(char *dev,u_long ip_src,u_long ip_dst,u_short sport,u_short dport)
{
   char errbuf[256];
   struct libnet_ipv4_hdr *ip;
   struct libnet_tcp_hdr *tcp;
   pcap_t* descr;
   pcap_dumper_t *dumper;
   int k;
   
   logd = stdout;
   nmax = 2;
   nconn = 0;
   lines = 1;
   z=0;

   tcpdl = "STREAM";

   if((descr=pcap_open_live(dev,BUFSIZ,1,0,errbuf)) == NULL)
     {
	w_error(1, "pcap_open_live: %s", errbuf);
     }

     /* create dumper for log the datas */
   if ((dumper = pcap_dump_open(descr,tcpdl))==NULL)
     {
	w_error(1, "pcap_open_live() error: %s\n\n",errbuf);
     }

   offset=(device(dev,descr));

   for(k=0;k<30;k++)
     {
	memset(&c_inf[k], 0, sizeof(c_inf[k]));
	memset(&sf[k].string, 0, sizeof(sf[k].string));
	memset(&sf[k].sfilter, 0, sizeof(sf[k].sfilter));
     }

   init_scr();

   mvwprintw(winfo->win,0,2,"Source");
   mvwprintw(winfo->win,0,21,"Port");
   mvwprintw(winfo->win,0,34,"Destination");
   mvwprintw(winfo->win,0,55,"Port");
   mvwprintw(winfo->win,0,66,"State");
   SAFE_SCROLL_REFRESH(winfo);

   while(1)
     {

	if ((packet = (u_char *) pcap_next (descr, &hdr))!=NULL)
	  {  
	     fflush((FILE *)dumper);
             pcap_dump((u_char *)dumper,&hdr,packet);

	     ip = (struct libnet_ipv4_hdr *) (packet + offset);
	     tcp = (struct libnet_tcp_hdr *) (packet + offset + LIBNET_IPV4_H);

	     if (ip->ip_p == IPPROTO_TCP)
	       {
		  if (!sport && !dport)
		    {
		       if ( ip->ip_src.s_addr == ip_src && ip->ip_dst.s_addr == ip_dst)
			 {
			    switch(tcp->th_flags)
			      {
			       case TH_SYN:
				 add(ip_src,ip_dst,htons(tcp->th_sport),htons(tcp->th_dport));
				 break;
			       case TH_ACK:
				 break;
			       case TH_RST:
				 del(ip_src,ip_dst,htons(tcp->th_sport),htons(tcp->th_dport),Rst);
				 break;
			       case (TH_ACK|TH_PUSH):
				 break;
			       case (TH_URG|TH_ACK):
				 break;
			       case (TH_FIN|TH_ACK):
				 del(ip_src,ip_dst,htons(tcp->th_sport),htons(tcp->th_dport),Fin);
			       case (TH_RST|TH_ACK):
				 del(ip_src,ip_dst,htons(tcp->th_sport),htons(tcp->th_dport),Rst);
				 break;

			       default:
				 break;
			      }
			 }
        		/* caso rovescio */
		       else if ( ip->ip_src.s_addr == ip_dst && ip->ip_dst.s_addr == ip_src )
			 {
			    switch(tcp->th_flags)
			      {
			       case TH_SYN:
				 add(ip_dst,ip_src,htons(tcp->th_sport),htons(tcp->th_dport));
				 break;
			       case TH_ACK:
				 break;
			       case TH_RST:
				 del(ip_dst,ip_src,htons(tcp->th_sport),htons(tcp->th_dport),Rst);
				 break;
			       case (TH_ACK|TH_PUSH):
				 break;
			       case (TH_URG|TH_ACK):
				 break;
			       case (TH_FIN|TH_ACK):
				 del(ip_dst,ip_src,htons(tcp->th_sport),htons(tcp->th_dport),Fin);
			       case (TH_RST|TH_ACK):
				 del(ip_dst,ip_src,htons(tcp->th_sport),htons(tcp->th_dport),Rst);
				 break;

			       default:
				 break;
			      }
			 }
		    }
	       }

	  }

     }

   pcap_close(descr);
   pcap_dump_close(dumper);

   return 0;
}

int add(u_long ip_src,u_long ip_dst,u_short sport,u_short dport)
{
   int i;
   for(i=0;i<30;i++)
     if((ip_src==c_inf[i].s_ip && ip_dst==c_inf[i].d_ip && sport==c_inf[i].s_port && dport==c_inf[i].d_port) || (ip_src==c_inf[i].d_ip && ip_dst==c_inf[i].s_ip && sport==c_inf[i].d_port && dport==c_inf[i].s_port))
       return(0); /*ce l'ho gi� (duplicato)*/

   for(i=0;i<30;i++)/*cerco spazio vuoto*/
     {
	if(c_inf[i].s_ip)continue;
	else
	  {
	     c_inf[i].s_ip = ip_src;
	     c_inf[i].d_ip = ip_dst;
	     c_inf[i].s_port = sport;
	     c_inf[i].d_port = dport;

	     mvwprintw(winfo->win,lines,2,"%s",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE));
	     mvwprintw(winfo->win,lines,21,"%d",c_inf[i].s_port);
	     mvwprintw(winfo->win,lines,34,"%s",libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE));
	     mvwprintw(winfo->win,lines,55,"%d",c_inf[i].d_port);
	     mvwprintw(winfo->win,lines,66,"Open");
	     SAFE_SCROLL_REFRESH(winfo);

	     sprintf(sf[z].string,        "%2s%12d%20s%12d         Open",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE),c_inf[i].s_port,libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE),c_inf[i].d_port);
	     /* create the filter for tcp stream*/
	     sprintf(sf[z].sfilter,"host %s and port %d and host %s and port %d",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE),c_inf[i].s_port,libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE),c_inf[i].d_port);
	     c_inf[i].lin=lines;

	     sf[i].cont=z;
	     nconn++;
	     lines++;
	     z++;
	     ++nmax;
	     return(1);
	  }
	  
   
     }
   return(0);
}

int del(u_long ip_src,u_long ip_dst,u_short sport,u_short dport, int flag)
{
   int i;

   for(i=0;i<30;i++)
     {
	if(ip_src==c_inf[i].s_ip && ip_dst==c_inf[i].d_ip && sport==c_inf[i].s_port && dport==c_inf[i].d_port)
	  { if(flag){
	     mvwprintw(winfo->win,c_inf[i].lin,2,"%s",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE));
	     mvwprintw(winfo->win,c_inf[i].lin,21,"%d",c_inf[i].s_port);
	     mvwprintw(winfo->win,c_inf[i].lin,34,"%s",libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE));
	     mvwprintw(winfo->win,c_inf[i].lin,55,"%d",c_inf[i].d_port);
	     mvwprintw(winfo->win,c_inf[i].lin,66,"Closed");

	     sprintf(sf[sf[i].cont].string,"%2s%12d%20s%14d       Closed",
		     libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE),c_inf[i].s_port,libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE),c_inf[i].d_port);
	  }
	     else
	       {
		  mvwprintw(winfo->win,c_inf[i].lin,2,"%s",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE));
		  mvwprintw(winfo->win,c_inf[i].lin,21,"%d",c_inf[i].s_port);
		  mvwprintw(winfo->win,c_inf[i].lin,34,"%s",libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE));
		  mvwprintw(winfo->win,c_inf[i].lin,55,"%d",c_inf[i].d_port);
		  mvwprintw(winfo->win,c_inf[i].lin,66,"Resetted");

		  sprintf(sf[sf[i].cont].string,    "%2s%12d%20s%13d        Resetted",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE),c_inf[i].s_port,libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE),c_inf[i].d_port);
	       }
	     sprintf(sf[sf[i].cont].sfilter,"host %s and port %d and host %s and port %d",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE),c_inf[i].s_port,libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE),c_inf[i].d_port);
	     SAFE_SCROLL_REFRESH(winfo);
	     //wrefresh(winfo->win);
	     memset(&c_inf[i], 0, sizeof(c_inf[i]));
	     nconn--;

	  }
	else if(ip_src==c_inf[i].d_ip && ip_dst==c_inf[i].s_ip && sport==c_inf[i].d_port && dport==c_inf[i].s_port)
	  { if(flag){
	     mvwprintw(winfo->win,c_inf[i].lin,2,"%s",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE));
	     mvwprintw(winfo->win,c_inf[i].lin,21,"%d",c_inf[i].s_port);
	     mvwprintw(winfo->win,c_inf[i].lin,34,"%s",libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE));
	     mvwprintw(winfo->win,c_inf[i].lin,55,"%d",c_inf[i].d_port);
	     mvwprintw(winfo->win,c_inf[i].lin,66,"Closed");

	     sprintf(sf[sf[i].cont].string,      "%2s%12d%20s%14d       Closed",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE),c_inf[i].s_port,libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE),c_inf[i].d_port);
	  }
	     else
	       {
		  mvwprintw(winfo->win,c_inf[i].lin,2,"%s",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE));
		  mvwprintw(winfo->win,c_inf[i].lin,21,"%d",c_inf[i].s_port);
		  mvwprintw(winfo->win,c_inf[i].lin,34,"%s",libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE));
		  mvwprintw(winfo->win,c_inf[i].lin,55,"%d",c_inf[i].d_port);
		  mvwprintw(winfo->win,c_inf[i].lin,66,"Resetted");

		  sprintf(sf[sf[i].cont].string,      "%2s%12d%20s%13d        Resetted",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE),c_inf[i].s_port,libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE),c_inf[i].d_port);
	       }
	     sprintf(sf[sf[i].cont].sfilter,"host %s and port %d and host %s and port %d",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE),c_inf[i].s_port,libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE),c_inf[i].d_port);
	     SAFE_SCROLL_REFRESH(winfo);
	     memset(&c_inf[i], 0, sizeof(c_inf[i]));
	     nconn--;

	  }

     }
   return -1;
}

#endif

