/*
 *
 * Copyright 2012, Stéphan Kochen <stephan@kochen.nl>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <stdio.h>  
#include <time.h>  

/*
struct timespec {
time_t tv_sec; // seconds
long tv_nsec; // and nanoseconds
};
*/
int main()  
{  
    struct timespec time1 = {0, 0};  
    clock_gettime(CLOCK_MONOTONIC, &time1);  
    printf("CLOCK_MONOTONIC: %d, %d", time1.tv_sec, time1.tv_nsec);  
    printf("\n%d\n", time(NULL));  
    sleep(1);  
} 