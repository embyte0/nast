/*
    nast - Network analyzer sniffer tool

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

#define BYTES	16
#define SHORTS	(BYTES / 2)
#define DIGITS	5
#define LINE	(DIGITS * SHORTS)

void print_ascii_hex(char *data, u_int l, FILE *log)
{
   u_int offset;
   u_int i;
   int s1, s2;
   int nshorts;
   char hex[BYTES*DIGITS+1], *hsp;
   char ascii[BYTES+1], *asp;

   row_s=0;
   line_s+=3;

   nshorts = l / sizeof(u_short);
   offset = i = 0;
   hsp = hex; asp = ascii;
   while (--nshorts >= 0)
     {
	s1 = *data++;
	s2 = *data++;
	(void)snprintf(hsp, sizeof(hex) - (hsp - hex),
		       " %02x%02x", s1, s2);
	hsp += DIGITS;
	*(asp++) = (isgraph(s1) ? s1 : '.');
	*(asp++) = (isgraph(s2) ? s2 : '.');
	if (++i >= SHORTS)
	  {
	     *hsp = *asp = '\0';
	     /*fprintf(log, "\n0x%04x   %-*s    %s",
		     offset, LINE,
		     hex, ascii);*/
	     if(!graph) printf("\n");
	     n_print("princ",line_s,row_s,lg,"0x%04x   %-*s    %s",
		     offset, LINE,
		     hex, ascii);
	     i = 0; hsp = hex; asp = ascii;
	     offset += BYTES;
	     ++line_s;
	  }
     }
   if (l & 1)
     {
	s1 = *data++;
	(void)snprintf(hsp, sizeof(hex) - (hsp - hex),
		       " %02x", s1);
	hsp += 3;
	*(asp++) = (isgraph(s1) ? s1 : '.');
	++i;
     }
   if (i > 0)
     {
	*hsp = *asp = '\0';
	if(!graph) printf("\n");
	n_print("princ",line_s,row_s,lg,"0x%04x   %-*s    %s",
		offset, LINE,
		hex, ascii);
	++line_s;
     }
}

void data_sniffo (char *data_info, u_int len, FILE *log)
{
   int i,ld;

   row_s = ld = 0;

   if(log==stdout)
     ld = 0;
   else ld = 1;

   line_s+=3;

   if(graph && !ld)
     {

	if (data_info == NULL)
	  {
	     n_print("princ",line_s,row_s,lg,"NULL DATA");
	     ++line_s;
	  }

	for (i = 0; i < len; i++)
	  {
	     if (ispunct(data_info[i]) || isalnum(data_info[i]))
	       {
		  n_print("princ",line_s,row_s,lg,"%c",data_info[i]);
		  row_s++;
	       }
	     else if (data_info[i]=='\n')
	       {
		  n_print("princ",++line_s,row_s,lg,"");
		  row_s=0;
	       }
	     else if (data_info[i]=='\r')
	       row_s = row_s + 5;
	     else if (data_info[i]=='\t')
	       row_s = row_s + 3;
	     else
	       row_s++;

	  }

     }

   if(!graph || (graph && ld))
     {
        fputc('\n', log);
	line_s-=3;

	if (data_info == NULL)
	  fprintf(log, "NULL DATA\n");

	for (i = 0; i < len; i++)
	  {
	     if (ispunct(data_info[i]) || isalnum(data_info[i]))
	       fputc (data_info[i], log);
	     else if (data_info[i]=='\n')
	       fputc('\n', log);
	     else if (data_info[i]=='\r')
	       fputc('\r', log);
	     else if (data_info[i]=='\t')
	       fputc ('\t', log);
	     else
	       fputc (' ', log);
	  }
     }

}

