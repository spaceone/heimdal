/*
 * Copyright (c) 1997, 1998 Kungliga Tekniska H�gskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. All advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement: 
 *      This product includes software developed by Kungliga Tekniska 
 *      H�gskolan and its contributors. 
 *
 * 4. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

#include "krb5_locl.h"

RCSID("$Id$");
			
krb5_error_code
krb5_sock_to_principal (krb5_context context,
			int sock,
			const char *sname,
			int32_t type,
			krb5_principal *ret_princ)
{
    krb5_error_code ret;
    krb5_address address;
    int len = krb5_max_sockaddr_size ();
    char *buf = malloc(len);
    struct sockaddr *sa;
    struct hostent *hostent;
    int family;
    char hname[256];

    if (buf == NULL)
	return ENOMEM;
    sa = (struct sockaddr *)buf;

    if (getsockname (sock, sa, &len) < 0) {
	free (buf);
	return errno;
    }
    family = sa->sa_family;
    
    ret = krb5_sockaddr2address (sa, &address);
    free (buf);
    if (ret)
	return ret;

    hostent = roken_gethostbyaddr (address.address.data,
				   address.address.length,
				   family);

    if (hostent == NULL)
	return h_errno;
    strcpy_truncate(hname, hostent->h_name, sizeof(hname));
    return krb5_sname_to_principal (context,
				    hname,
				    sname,
				    type,
				    ret_princ);
}
