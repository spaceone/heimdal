/*
 * Copyright (c) 1997 Kungliga Tekniska H�gskolan
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

#include <krb5_locl.h>
#include "crc.h"

RCSID("$Id$");

struct encryption_type {
    int type;
    size_t blocksize;
    size_t confoundersize;
    void (*encrypt)(void *, size_t, const krb5_keyblock *, int);
    krb5_keytype keytype;
    krb5_cksumtype cksumtype;
};

static void
NULL_encrypt(void *p, size_t len, const krb5_keyblock *keyblock, int encrypt)
{
}

static void
DES_encrypt_null_ivec(void *p, size_t len, 
		      const krb5_keyblock *keyblock, int encrypt)
{
    des_cblock key;
    des_cblock ivec;
    des_key_schedule schedule;
    memcpy(&key, keyblock->keyvalue.data, sizeof(key));
    des_set_key(&key, schedule);
    memset (&ivec, 0, sizeof(ivec));
    des_cbc_encrypt(p, p, len, schedule, &ivec, encrypt);
}

static void
DES_encrypt_key_ivec(void *p, size_t len, 
		     const krb5_keyblock *keyblock, int encrypt)
{
    des_cblock key;
    des_key_schedule schedule;
    memcpy(&key, keyblock->keyvalue.data, sizeof(key));
    des_set_key(&key, schedule);
    des_cbc_encrypt(p, p, len, schedule, &key, encrypt);
}

static void
DES3_encrypt(void *p, size_t len, const krb5_keyblock *keyblock, int encrypt)
{
    abort ();
}

static struct encryption_type em [] = {
    { ETYPE_DES_CBC_CRC, 8, 8, DES_encrypt_key_ivec,
      KEYTYPE_DES,  CKSUMTYPE_CRC32 },
    { ETYPE_DES_CBC_MD4, 8, 8, DES_encrypt_null_ivec,
      KEYTYPE_DES,  CKSUMTYPE_RSA_MD4 },
    { ETYPE_DES_CBC_MD5, 8, 8, DES_encrypt_null_ivec,
      KEYTYPE_DES,  CKSUMTYPE_RSA_MD5 },
    { ETYPE_NULL,        1, 0, NULL_encrypt, KEYTYPE_NULL, CKSUMTYPE_NONE },
};

static int num_etypes = sizeof(em) / sizeof(em[0]);

static struct encryption_type *
find_encryption_type(int etype)
{
    struct encryption_type *e;
    for(e = em; e < em + num_etypes; e++)
	if(etype == e->type)
	    return e;
    return NULL;
}

krb5_error_code
krb5_etype2keytype(krb5_context context,
		   krb5_enctype etype,
		   krb5_keytype *keytype)
{
    struct encryption_type *e;
    e = find_encryption_type(etype);
    if(e == NULL)
	return KRB5_PROG_ETYPE_NOSUPP;
    *keytype = e->keytype;
    return 0;
}

void
krb5_generate_random_block(void *buf, size_t len)
{
    des_cblock tmp;
    unsigned char *p = buf;
    size_t l;
    while(len){
	des_new_random_key(&tmp);
	l = len > 8 ? 8 : len;
	memcpy(p, tmp, l);
	p += l;
	len -= l;
    }
}

static krb5_error_code
krb5_do_encrypt(krb5_context context,
		void *ptr, 
		size_t len,
		struct encryption_type *et,
		const krb5_keyblock *keyblock,
		krb5_data *result)
{
    size_t sz;
    size_t checksumsize;
    unsigned char *p;
    krb5_error_code ret;
    Checksum cksum;
    
    ret = krb5_cksumsize(context, et->cksumtype, &checksumsize);
    if(ret)
	return ret;
    sz = len + et->confoundersize + checksumsize;
    sz = (sz + et->blocksize - 1) & ~ (et->blocksize - 1);
    p = calloc(1, sz);
    if (p == NULL)
	return ENOMEM;
    krb5_generate_random_block(p, et->confoundersize); /* XXX */
    memcpy(p + et->confoundersize + checksumsize, ptr, len);

    krb5_create_checksum(context, et->cksumtype, p, sz, NULL, &cksum);
    memcpy(p + et->confoundersize, cksum.checksum.data, checksumsize);
    free_Checksum(&cksum);
    (*et->encrypt)(p, sz, keyblock, 1);
    result->data = p;
    result->length = sz;
    return 0;
}

static krb5_error_code
krb5_do_decrypt(krb5_context context,
		void *ptr,
		size_t len,
		struct encryption_type *et,
		const krb5_keyblock *keyblock,
		krb5_data *result)
{
    unsigned char *p = ptr;
    size_t outlen;
    Checksum cksum;
    krb5_error_code ret;

    cksum.cksumtype = et->cksumtype;
    ret = krb5_cksumsize(context, cksum.cksumtype, &cksum.checksum.length);
    if(ret)
	return ret;
    outlen = len - et->confoundersize - cksum.checksum.length;
    cksum.checksum.data = malloc(cksum.checksum.length);
    if(cksum.checksum.data == NULL)
	return ENOMEM;
    (*et->encrypt)(ptr, len, keyblock, 0);

    memcpy(cksum.checksum.data, p + et->confoundersize, cksum.checksum.length);
    memset(p + et->confoundersize, 0, cksum.checksum.length);
    
    ret = krb5_verify_checksum (context,
				ptr, 
				len,
				keyblock,
				&cksum);
    free_Checksum(&cksum);
    if(ret)
	return ret;
    
    result->data = malloc(outlen);
    if(result->data == NULL)
	return ENOMEM;
    result->length = outlen;
    memcpy(result->data, p + (len - outlen), outlen);
    return 0;
}

krb5_error_code
krb5_encrypt (krb5_context context,
	      void *ptr,
	      size_t len,
	      int etype,
	      const krb5_keyblock *keyblock,
	      krb5_data *result)
{
    struct encryption_type *e;
    if((e = find_encryption_type(etype)))
	return krb5_do_encrypt(context, ptr, len, e, keyblock, result);
    return KRB5_PROG_ETYPE_NOSUPP;
}

krb5_error_code
krb5_encrypt_EncryptedData(krb5_context context,
			   void *ptr,
			   size_t len,
			   int etype,
			   int kvno,
			   const krb5_keyblock *keyblock,
			   EncryptedData *result)
{
    result->etype = etype;
    if(kvno){
	result->kvno = malloc(sizeof(*result->kvno));
	*result->kvno = kvno;
    }else
	result->kvno = NULL;
    return krb5_encrypt(context, ptr, len, etype, keyblock, &result->cipher);
}

krb5_error_code
krb5_decrypt (krb5_context context,
	      void *ptr,
	      size_t len,
	      int etype,
	      const krb5_keyblock *keyblock,
	      krb5_data *result)
{
    struct encryption_type *e;
    if((e = find_encryption_type(etype)))
	return krb5_do_decrypt(context, ptr, len, e, keyblock, result);
    return KRB5_PROG_ETYPE_NOSUPP;
}
