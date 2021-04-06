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

/* Find pcap_datalink */

int device (char *dev, pcap_t* descr)
{
   char errbuf[PCAP_ERRBUF_SIZE];
   u_short off;

   off = 0;

   if ((datalink = pcap_datalink(descr)) < 0)
     {
	w_error(1, "Error: pcap_datalink: %s\n", errbuf);
     }
   switch (datalink)
     {
      case DLT_EN10MB:
	off = 14;
	break;
      case DLT_NULL:
      case DLT_PPP:
	off = 4;
	break;
      /*for OpenBSD. If this offset doesn't work change it in 108*/
      case DLT_LOOP:
        off=12;
	break;
      case DLT_SLIP:
	off = 16;
	break;
      case DLT_RAW:
	off = 0;
	break;
      case DLT_SLIP_BSDOS:
      case DLT_PPP_BSDOS:
	off = 24;
	break;
      case DLT_FDDI:
	off = 21;
	break;
      case DLT_LINUX_SLL:
        off = 16;
	break;
      default:
	w_error(1, "Error: Unknown Datalink Type: (%d)\n", datalink);
     }
   return(off);
}
