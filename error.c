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

/*  fatal error = 1
non-fatal error = 0
*/

#include "include/nast.h"
#include <stdarg.h>

int w_error(int fatal, char *err, ...);

int w_error(int fatal, char *err, ...)
{
   char error[100];
   int n,ris;
   va_list ap;
   ris = 0;

   va_start(ap, err);
   n = vsnprintf(error, 100, err, ap);
   va_end(ap);

#ifdef HAVE_LIBNCURSES
   if(graph){
     n_error(error, fatal);
     return -1;/*it returns -1 only if the error isn't fatal! */
     }
#endif

   fprintf(stderr, "\n%s\n\n", error);
   exit(-1);
}

