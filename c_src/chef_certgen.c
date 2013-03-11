/*-----------------------------------------------------------------
  opscode_crypto.c
  Christopher Brown <cb@opscode.com>
  (C) 2010 - 2012 Opscode, Inc.


  Created : 25 Nov 2010 by Christopher Brown <cb@opscode.com>

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-------------------------------------------------------------------*/

#include "erl_nif.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

static ERL_NIF_TERM rsa_generate_key_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM x509_make_cert_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

typedef struct _x509_subject_entry {
  char* name;
  char* value;
} x509_subject_entry;

static int x509_parse_subject(ErlNifEnv* env, ERL_NIF_TERM subject_terms, int *num_subject_entries, x509_subject_entry **subject_entries);
static int x509_parse_keypair(ErlNifEnv* env, const char *keypair_name, ERL_NIF_TERM key_tuple, char *keys[2]);
static int x509_parse_issuer_cert(ErlNifEnv* env, ERL_NIF_TERM issuer_cert_tuple, char **issuer_cert_pem);
static int binary_to_string(ErlNifEnv* env, ERL_NIF_TERM bin_term, char **bin_str);
static int atom_to_string(ErlNifEnv* env, ERL_NIF_TERM atom_term, char **bin_str);

static ErlNifFunc nif_funcs[] =
{
    {"rsa_generate_key_nif", 1, rsa_generate_key_nif},
    {"x509_make_cert_nif", 1, x509_make_cert_nif}
};

static ERL_NIF_TERM atom_error;
static ERL_NIF_TERM atom_ok;
static ERL_NIF_TERM atom_bad_keylen;
static ERL_NIF_TERM atom_x509_cert;
static ERL_NIF_TERM atom_bad_ssl_init;

#define KEYPAIR_STR "keypair"
#define PUBLIC_KEY_STR "public_key"
#define PRIVATE_KEY_STR "private_key"
#define ISSUER_CERT_STR "issuer_cert"
#define SUBJECT_STR "subject"

static int keypair_strlen;
static int public_key_strlen;
static int private_key_strlen;
static int issuer_cert_strlen;
static int subject_strlen;
static const EVP_MD *digest;

/* NIF interface declarations */
static int load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info);
static int upgrade(ErlNifEnv* env, void** priv_data, void** old_priv_data, ERL_NIF_TERM load_info);

static int load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info)
{
    keypair_strlen = strlen(KEYPAIR_STR);
    public_key_strlen = strlen(PUBLIC_KEY_STR);
    private_key_strlen = strlen(PRIVATE_KEY_STR);
    issuer_cert_strlen = strlen(ISSUER_CERT_STR);
    subject_strlen = strlen(SUBJECT_STR);
    digest = EVP_sha1();

    atom_bad_ssl_init = enif_make_atom(env,"bad_ssl_init");
    atom_bad_keylen = enif_make_atom(env,"bad_keylen");
    atom_error = enif_make_atom(env,"error");
    atom_ok = enif_make_atom(env,"ok");
    atom_x509_cert = enif_make_atom(env, "x509_cert");

    return 0;
}

static int upgrade(ErlNifEnv* env, void** priv_data, void** old_priv_data,
                   ERL_NIF_TERM load_info)
{
    load(env, priv_data, load_info);
    return 0;
}

static ERL_NIF_TERM rsa_generate_key_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM ret;
  ERL_NIF_TERM private_keyterm, public_keyterm;
  BIO *bio_private_pem=NULL, *bio_public_pem=NULL;
  RSA *rsa = NULL;
  BIGNUM *bn_rsa_genkey=NULL;
  int rsa_keylen=-1;
  int private_pemlen, public_pemlen;
  unsigned long f4=RSA_F4;
  int dlen;

  /* BUGBUG: Need better validation of key length here [cb] */
  if (!enif_get_int(env, argv[0], &rsa_keylen)) {
	return enif_make_badarg(env);
  }

  /* Do all allocations and fail function call if any single alloc failed */
  rsa = RSA_new();
  bn_rsa_genkey = BN_new();
  bio_private_pem = BIO_new(BIO_s_mem());
  bio_public_pem = BIO_new(BIO_s_mem());

  /* Do actual OpenSSL work */
  if(rsa && bn_rsa_genkey && bio_private_pem && bio_public_pem){
    BN_set_word(bn_rsa_genkey, f4);

    if (RSA_generate_key_ex(rsa, rsa_keylen, bn_rsa_genkey, NULL)) {
      unsigned char *private_pemdata;
      unsigned char *public_pemdata;

      PEM_write_bio_RSA_PUBKEY(bio_public_pem,rsa);
      PEM_write_bio_RSAPrivateKey(bio_private_pem,rsa,NULL,NULL,0,NULL,NULL);
        
      private_pemlen = BIO_get_mem_data(bio_private_pem, &private_pemdata);
      public_pemlen = BIO_get_mem_data(bio_public_pem, &public_pemdata);
        
      dlen = sizeof(int)+private_pemlen+sizeof(int)+public_pemlen;
      private_pemdata[private_pemlen]=0;
      public_pemdata[public_pemlen]=0;

      memcpy(enif_make_new_binary(env, private_pemlen, &private_keyterm), private_pemdata, private_pemlen);
      memcpy(enif_make_new_binary(env, public_pemlen, &public_keyterm), public_pemdata, public_pemlen);
      ret = enif_make_tuple3(env, atom_ok, public_keyterm, private_keyterm);
    }
    else {
      ret = enif_make_tuple2(env, atom_error, atom_bad_keylen);
    }

  } else {
    ret = enif_make_tuple2(env, atom_error, atom_bad_ssl_init);
  }

  /* dealloc */
  if(bio_private_pem)
    BIO_free_all(bio_private_pem);
  if(bio_public_pem)
    BIO_free_all(bio_public_pem);
  if(bn_rsa_genkey)
    BN_free(bn_rsa_genkey);
  if(rsa)
    RSA_free(rsa);

  return ret;
}

static int x509_parse_subject(ErlNifEnv* env, ERL_NIF_TERM subject_tuple, int *num_subject_entries, x509_subject_entry **subject_entries){
  int num_subject_tuple;
  unsigned num_subject_terms;
  ERL_NIF_TERM head, tail;
  int pair_arity;
  char *name;
  char *value;
  char *subject_string = NULL;
  const ERL_NIF_TERM* pair;
  int idx;
  x509_subject_entry* se;
  unsigned value_len;
  const ERL_NIF_TERM* subject_terms;

  *subject_entries = NULL;
  *num_subject_entries = 0;

  /* make sure this is a tuple with first term 'subject' */
  if(!enif_get_tuple(env, subject_tuple, &num_subject_tuple, &subject_terms) ||
     !atom_to_string(env, subject_terms[0], &subject_string) ||
     strncmp(subject_string, SUBJECT_STR, subject_strlen)) {
    if(subject_string) free(subject_string);
    return 0;
  }
  free(subject_string);

  /* create room for the x509_subject_entry structs */
  if(!enif_get_list_length(env, subject_terms[1], &num_subject_terms) || 
     (NULL == (se = (x509_subject_entry*)malloc(num_subject_terms * sizeof(x509_subject_entry))))) return 0;

  /* get the first entry and prime the pump for walking the rest */
  if(!enif_get_list_cell(env, subject_terms[1], &head, &tail) || 
     !enif_get_tuple(env, head, &pair_arity, &pair) ||
     pair_arity!=2) { return 0; }

  for(idx=0; idx<num_subject_terms; idx++){
    atom_to_string(env, pair[0], &name);

    enif_get_list_length(env, pair[1], &value_len);
    value = (char*)malloc(value_len+1);
    enif_get_string(env, pair[1], value, value_len+1, ERL_NIF_LATIN1);
    (se+idx)->name = name;
    (se+idx)->value = value;

    if(!enif_get_list_cell(env, tail, &head, &tail) || 
       !enif_get_tuple(env, head, &pair_arity, &pair) ||
       pair_arity!=2) { break; }
  }

  *num_subject_entries = num_subject_terms;
  *subject_entries = se;
  return 1;
}

static int binary_to_string(ErlNifEnv* env, ERL_NIF_TERM bin_term, char **bin_str)
{
  ErlNifBinary bin_bin;
  char *bin_buf = NULL;

  *bin_str = NULL;

  if(!enif_inspect_binary(env, bin_term, &bin_bin) || NULL == (bin_buf = (char*)malloc(bin_bin.size))) return 0;
  *bin_str = strncpy(bin_buf, (char*)bin_bin.data, bin_bin.size);
  return 1;
}

static int atom_to_string(ErlNifEnv* env, ERL_NIF_TERM atom_term, char **bin_str)
{
  unsigned atom_len;
  char *atom_string;
  
  *bin_str = NULL;

  if(!enif_is_atom(env, atom_term) || !enif_get_atom_length(env, atom_term, &atom_len, ERL_NIF_LATIN1)) return 0;
  if(!(atom_string  = (char*)malloc(atom_len+1))) return 0;
  if(!enif_get_atom(env, atom_term, atom_string, atom_len+1, ERL_NIF_LATIN1)){
    free(atom_string);
    return 0;
  }

  *bin_str = atom_string;
  return 1;
}

static int x509_parse_keypair(ErlNifEnv* env, const char* keypair_name, ERL_NIF_TERM key_tuple, char *keys[2]){
  /* key_tuple :=  {keypair_name, {keypair , [{public_key, <<...>>}, {private_key, <<..>>}]}} */
  unsigned atom_len = -1;
  int num_named_key_terms = -1;
  int num_keypair_terms = -1;
  int num_public_key_terms = -1;
  int num_private_key_terms = -1;
  const ERL_NIF_TERM *named_key_terms = NULL;
  const ERL_NIF_TERM *keypair_terms = NULL;
  const ERL_NIF_TERM *public_key_terms = NULL;
  const ERL_NIF_TERM *private_key_terms = NULL;
  char *keyname = NULL;
  char *keypair = NULL;
  char *private_key_str, *public_key_str;
  ERL_NIF_TERM head,tail;

  if ( NULL == keys || 
       NULL == keypair_name){
    return 0;
  }

  /* get the name of the key, which is given as an atom */
  if(!enif_get_tuple(env, key_tuple, &num_named_key_terms, &named_key_terms) || 
     !atom_to_string(env, named_key_terms[0], &keyname)){
    if(NULL != keyname) free(keyname);
    return 0;
  }

  if(strncmp(keyname, keypair_name, atom_len)){
    free(keyname);
    return 0;
  }

  /* get the tagged tuple representing the keypair */
  if(!enif_get_tuple(env, named_key_terms[1], &num_keypair_terms, &keypair_terms)) return 0;
  /* get the atom 'keypair' and validate */
  if(num_keypair_terms < 2) return 0;

  if(!atom_to_string(env, keypair_terms[0], &keypair) || strncmp(keypair, KEYPAIR_STR, atom_len)){
    if(keypair) free(keypair);
    return 0;
  }

  /* keypair itself is a list of tuples, one member is the public key, the other is the private key */
  enif_get_list_cell(env, keypair_terms[1], &head, &tail);
  enif_get_tuple(env, head, &num_public_key_terms, &public_key_terms);

  /* get the public key binary */
  if(!atom_to_string(env, public_key_terms[0], &keyname) ||
     strncmp(keyname, PUBLIC_KEY_STR, atom_len)){
    if(NULL != keyname) free(keyname);
    return 0;
  }
  free(keyname);
  keyname = NULL;

  if(!binary_to_string(env, public_key_terms[1], &public_key_str)) return 0;

  enif_get_list_cell(env, tail, &head, &tail);
  enif_get_tuple(env, head, &num_private_key_terms, &private_key_terms);

  /* get the private key binary */
  if(!atom_to_string(env, private_key_terms[0], &keyname) ||
     strncmp(keyname, PRIVATE_KEY_STR, atom_len)){
    if(NULL != keyname) free(keyname);
    return 0;
  }
  free(keyname);

  if(!binary_to_string(env, private_key_terms[1], &private_key_str)) return 0;

  keys[0] = public_key_str;
  keys[1] = private_key_str;
  return 1;
}

static int x509_parse_issuer_cert(ErlNifEnv* env, ERL_NIF_TERM issuer_cert_tuple, char **issuer_cert_pem)
{
  char *issuer_cert_atom_string = NULL;
  char *issuer_cert_pem_string = NULL;
  int num_issuer_terms;
  const ERL_NIF_TERM *issuer_terms;

  *issuer_cert_pem = NULL;

  if(NULL == issuer_cert_pem || !enif_get_tuple(env, issuer_cert_tuple, &num_issuer_terms, &issuer_terms)) return 0;
  if(!atom_to_string(env, issuer_terms[0], &issuer_cert_atom_string) || strncmp(issuer_cert_atom_string, ISSUER_CERT_STR, issuer_cert_strlen)) {
    if(NULL != issuer_cert_atom_string) free(issuer_cert_atom_string);
    return 0;
  }
  free(issuer_cert_atom_string);
  if(!binary_to_string(env, issuer_terms[1], &issuer_cert_pem_string)) return 0;
  
  *issuer_cert_pem = issuer_cert_pem_string;
  return 1;
}

/**
 * pull out the integer from a a tuple of the form {tuple_name, result_int},
 * where the tuple_name is an atom and the result_int is an integer.
 * 
 * so to parse:
 *   {expiry, 1234}
 *
 * call as:
 *   int expiry;
 *   x509_parse_int_tuple(env, arg_terms[idx++], "expiry", &expiry);
 */
static int x509_parse_int_tuple(ErlNifEnv* env, ERL_NIF_TERM tuple, char* tuple_name, int *result_int){
  int num_tuple;
  char *tuple_string = NULL;
  const ERL_NIF_TERM* tuple_terms;

  /* make sure this is a tuple with first term (tuple_name) */
  if(!enif_get_tuple(env, tuple, &num_tuple, &tuple_terms) ||
     num_tuple != 2 ||
     !atom_to_string(env, tuple_terms[0], &tuple_string) ||
     strncmp(tuple_string, tuple_name, strlen(tuple_name))) {
    if(NULL != tuple_string) free(tuple_string);
    return 0;
  }
  
  /* get the value */
  enif_get_int(env, tuple_terms[1], result_int);

  return 1;
}

static int free_keys(char *keys[2]){
  int idx;
  for(idx=0; idx<2; idx++){
    if(keys[idx]) free(keys[idx]);
  }
  return 1;
}

static int free_subject_entries(int num_subject_entries, x509_subject_entry *subject_entries){
  for(; num_subject_entries>0; num_subject_entries--){
    free((subject_entries+num_subject_entries)->value);
    free(subject_entries+num_subject_entries);
  }
  return 1;
}

static ERL_NIF_TERM x509_make_cert_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  int expiry, serial;
  ASN1_INTEGER *asn1serial = NULL;
  BIGNUM *bn_rsa_genkey=NULL;
  BIO *bio_signing_private=NULL, *bio_issuer_cert = NULL, *bio_newcert_public = NULL;
  BIO *bio_x509=NULL;
  char *issuer_cert_pem=NULL;
  X509 *pX509 = NULL;
  X509 *pIssuerX509 = NULL;
  X509_NAME *pX509Name = NULL;
  X509_NAME *pIssuerName = NULL;
  x509_subject_entry *subject_entries;
  int num_subject_entries;
  int iret = 0;
  RSA *rsa=NULL;
  unsigned long f4=RSA_F4;
  unsigned args_len=-1;
  char *signing_keys[2], *cert_keys[2];
  ERL_NIF_TERM tail, *arg_terms=NULL;
  int idx;
  ERL_NIF_TERM ret, x509term;
  int x509len;
  unsigned char *x509data;

  EVP_PKEY *evp_signing_private = EVP_PKEY_new();
  EVP_PKEY *evp_newcert_public_key = EVP_PKEY_new();
  /* set RSA key gen type */
  bn_rsa_genkey = BN_new();
  BN_set_word(bn_rsa_genkey, f4);

  //
  // 1. stick subject of CA cert into NewCert
  // 2. stick public key of NewKeypair into NewCert
  // 3. sign NewCert with CA keypair

  /* Should be 6 elements in the list of X509 parameters.  We'll check each */
  if(!enif_get_list_length(env, argv[0], &args_len) || args_len != 6 ||
     NULL == (arg_terms = (ERL_NIF_TERM*)malloc(args_len * sizeof(ERL_NIF_TERM)))) return enif_make_badarg(env);
  
  enif_get_list_cell(env, argv[0], &arg_terms[0], &tail);
  for(idx=1; idx<args_len; idx++){
    if(!enif_get_list_cell(env, tail, &arg_terms[idx], &tail)){
      free(arg_terms);
      return enif_make_badarg(env);
    }
  }
  
  idx=0;
  /* get the signing private key */
  x509_parse_keypair(env, "signing_key", arg_terms[idx++], signing_keys);

  /* get the issuer cert */
  x509_parse_issuer_cert(env, arg_terms[idx++], &issuer_cert_pem);

  /* get the soon-to-be cert's public key */
  x509_parse_keypair(env, "newcert_public_key", arg_terms[idx++], cert_keys);

  /* get the subject */
  x509_parse_subject(env, arg_terms[idx++], &num_subject_entries, &subject_entries);

  /* get the serial number */
  x509_parse_int_tuple(env, arg_terms[idx++], "serial", &serial);

  /* get the expiry */
  x509_parse_int_tuple(env, arg_terms[idx++], "expiry", &expiry);

  /* work the OpenSSL cert creation magic */
  if ((bio_signing_private = BIO_new_mem_buf(signing_keys[1], -1))
      && (rsa = PEM_read_bio_RSAPrivateKey(bio_signing_private, NULL, NULL, NULL))
      && (iret = EVP_PKEY_assign_RSA(evp_signing_private, rsa))
              
      && (bio_newcert_public = BIO_new_mem_buf(cert_keys[0], -1))
      && (evp_newcert_public_key = PEM_read_bio_PUBKEY(bio_newcert_public, NULL, NULL, NULL))
              
      && (bio_issuer_cert = BIO_new_mem_buf(issuer_cert_pem, -1))
      && (pIssuerX509 = PEM_read_bio_X509(bio_issuer_cert, NULL, NULL, NULL))
      && (pX509 = X509_new())) {
    /* if we've managed to generate a key and allocate structure memory,
       set X509 fields */
    asn1serial = ASN1_INTEGER_new();
    X509_set_version(pX509, 2); /* cert_helper uses '3' here */
    ASN1_INTEGER_set(asn1serial, serial);
    X509_set_serialNumber(pX509, asn1serial);
    X509_gmtime_adj(X509_get_notBefore(pX509),0);
    X509_gmtime_adj(X509_get_notAfter(pX509),(long)60*60*24*expiry);
    X509_set_pubkey(pX509, evp_newcert_public_key);
    pX509Name = X509_get_subject_name(pX509);
    
    while(--num_subject_entries >= 0){
      X509_NAME_add_entry_by_txt(pX509Name, (subject_entries[num_subject_entries]).name,
                                 MBSTRING_ASC, (unsigned char*)(subject_entries[num_subject_entries]).value, -1, -1, 0);
    }
    
    pIssuerName = X509_get_issuer_name(pIssuerX509);
    X509_set_issuer_name(pX509, pIssuerName);
    X509_sign(pX509, evp_signing_private, digest);
    
    bio_x509 = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio_x509, pX509);
    
    x509len = BIO_get_mem_data(bio_x509, &x509data);
    memcpy(enif_make_new_binary(env, x509len, &x509term), x509data, x509len);
    ret = enif_make_tuple2(env, atom_x509_cert, x509term);
  }
    
 done:
  if(arg_terms) free(arg_terms);
  free_keys(signing_keys);
  free_keys(cert_keys);
  free_subject_entries(num_subject_entries, subject_entries);
  if(pX509) X509_free(pX509);
  if(pIssuerX509) X509_free(pIssuerX509);
  if(issuer_cert_pem) free(issuer_cert_pem);
  if(bio_issuer_cert) { BIO_set_close(bio_issuer_cert, BIO_NOCLOSE); BIO_free_all(bio_issuer_cert); }
  if(bio_signing_private) { BIO_set_close(bio_signing_private, BIO_NOCLOSE); BIO_free_all(bio_signing_private); }
  if(bio_newcert_public) { BIO_set_close(bio_newcert_public, BIO_NOCLOSE); BIO_free_all(bio_newcert_public); }
  if(bio_x509) BIO_free_all(bio_x509);
  if(asn1serial) ASN1_INTEGER_free(asn1serial);
  if(bn_rsa_genkey) BN_free(bn_rsa_genkey);
  if(rsa) RSA_free(rsa);

  return ret;
}

ERL_NIF_INIT(chef_certgen,nif_funcs,load,NULL,upgrade,NULL)
