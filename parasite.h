/* oblique 2010
 */
#ifndef PARASITE_H
#define PARASITE_H

#ifdef BUILD32

unsigned char parasite32[] = 
    "\x90";

#elif defined(BUILD64)

unsigned char parasite64[] = 
    "\x90";

#endif

#endif
