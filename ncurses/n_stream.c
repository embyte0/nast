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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HAVE_LIBNCURSES

void *read_packet(void *threadid);

int line = 1;
int col = 3;
int tmp;

struct stream_thread
{
   char s_dev[30];
   char s_sfilter[200];
};

struct stream_thread st_thread_data[1];

int streamg (char *dev, char *sfilter)
{

   line = 1;
   col = 3;
   
   tmp=line;

   werase(princ->win);
   winscroll(princ,-1000);
   SAFE_SCROLL_REFRESH(princ);

   /* if someone press enter without a filter selected */
   if(strstr(sfilter,"host") == NULL)
     return -1;

   strcpy(st_thread_data[0].s_dev,dev);
   strcpy(st_thread_data[0].s_sfilter,sfilter);
   pthread_create(&thID[5],NULL,read_packet,(void *) &st_thread_data[0]);

   return 0;

}

void data_sniffo_stream (char *data_info, u_int len)
{
   int i;

   if (data_info == NULL)
     {
	mvwprintw(princ->win,line,col,"NULL DATA");
	SAFE_SCROLL_REFRESH(princ);
	++line;
     }

   for (i = 0; i < len; i++)
     {
	if (ispunct(data_info[i]) || isalnum(data_info[i]))
	  {
	     mvwprintw(princ->win,line,col,"%c",data_info[i]);
	     SAFE_SCROLL_REFRESH(princ);
	     col++;
	  }
	else if (data_info[i]=='\n')
	  {
	     line++;
	     col=3;
	  }
	else if (data_info[i]=='\r')
	  col = col + 5;
	else if (data_info[i]=='\t')
	  col = col + 3;
	else
	  col++;

     }
     /*
	if(line>LINES-16 && line!=tmp)
	{
		winscroll(princ,+1);
		tmp=line;

	}*/

}


void *read_packet(void *threadid)
{
   char errbuf[LIBNET_ERRBUF_SIZE];
   struct libnet_ipv4_hdr *ip;
   struct libnet_tcp_hdr *tcp;
   pcap_t *s_str;
   char *data;
   int n;
   u_short TCP_SIZE_H;
   struct stream_thread *sdata;
   sdata = (struct stream_thread *) threadid;
   
   data = packet = NULL;
   

   if ((s_str = pcap_open_offline(tcpdl,errbuf))==NULL)
     {
	w_error(1, "pcap_open_offline() error: %s\n\n",errbuf);
     }

   
   if ((offset=(device(sdata->s_dev,s_str)))==-1)
     w_error(1, "Offset error");

   data = malloc (1024);

   if(pcap_compile(s_str,&fp,sdata->s_sfilter,0,netp) == -1)
     {
	w_error(1, "Error calling pcap_compile\n\n");
     }
   if(pcap_setfilter(s_str,&fp) == -1)
     {
	w_error(1, "Error calling pcap_setfilter\n\n");
     }

   while(1)
     {

	packet = (u_char *) pcap_next(s_str, &hdr);  
	if(packet==NULL) 
		continue;
	
	       
	ip = (struct libnet_ipv4_hdr *) (packet + offset);
	if (ip->ip_p != IPPROTO_TCP) continue;

	tcp = (struct libnet_tcp_hdr *) (packet + offset + LIBNET_IPV4_H);
	TCP_SIZE_H = tcp->th_off*4;

	n=ntohs(ip->ip_len) - LIBNET_IPV4_H - TCP_SIZE_H;
	data = (char *) (packet + offset + LIBNET_IPV4_H + TCP_SIZE_H);
	data_sniffo_stream(data, n);
	
	}
   pthread_exit(NULL);     
     
}
#endif

