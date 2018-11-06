/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal ASN1 structures and functions: not for application use */

/* ASN1 public key method structure */

// EVP_PKEY_ASN1_METHOD is a structure which holds a set of ASN.1 conversion, printing and information methods for a specific public key algorithm.
// There are two places where the EVP_PKEY_ASN1_METHOD objects are stored: one is a built-in array representing the standard methods for different algorithms, and the other one is a stack of user-defined application-specific methods, which can be manipulated by using EVP_PKEY_asn1_add0
struct evp_pkey_asn1_method_st {
    int pkey_id;
    int pkey_base_id;
    unsigned long pkey_flags;
    char *pem_str;
    char *info;
	//Decode X509_PUBKEY ASN.1 parameters to pk. It MUST return 0 on error, 1 on success. It's called by X509_PUBKEY_get0.
    int (*pub_decode) (EVP_PKEY *pk, X509_PUBKEY *pub);
	//Encode X509_PUBKEY ASN.1 parameters from pk. It MUST return 0 on error, 1 on success. It's called by X509_PUBKEY_set.
    int (*pub_encode) (X509_PUBKEY *pub, const EVP_PKEY *pk);
	//Compare two public keys. It MUST return 1 when the keys are equal, 0 otherwise. It's called by EVP_PKEY_cmp.
    int (*pub_cmp) (const EVP_PKEY *a, const EVP_PKEY *b);
	//Print a public key in humanly readable text to out, indented indent spaces. It MUST return 0 on error, 1 on success. It's called by EVP_PKEY_print_public.
    int (*pub_print) (BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx);
	//Decode PKCS8_PRIV_KEY_INFO form private key to pk. It MUST return 0 on error, 1 on success. It's called by EVP_PKCS82PKEY.
    int (*priv_decode) (EVP_PKEY *pk, const PKCS8_PRIV_KEY_INFO *p8inf);
	//Encode PKCS8_PRIV_KEY_INFO form private key from pk. It MUST return 0 on error, 1 on success. It's called by EVP_PKEY2PKCS8.
    int (*priv_encode) (PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pk);
	//Print a private key in humanly readable text to out, indented indent spaces. It MUST return 0 on error, 1 on success. It's called by EVP_PKEY_print_private.
    int (*priv_print) (BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx);
	//Returns the key size in bytes. It's called by EVP_PKEY_size.
    int (*pkey_size) (const EVP_PKEY *pk);
	//returns the key size in bits. It's called by EVP_PKEY_bits.
    int (*pkey_bits) (const EVP_PKEY *pk);
    int (*pkey_security_bits) (const EVP_PKEY *pk);
	//Decode DER formatted parameters to pkey. It MUST return 0 on error, 1 on success. It's called by PEM_read_bio_Parameters.
    int (*param_decode) (EVP_PKEY *pkey, const unsigned char **pder, int derlen);
	//Encode DER formatted parameters to pkey. It MUST return 0 on error, 1 on success. It's called by PEM_write_bio_Parameters.
    int (*param_encode) (const EVP_PKEY *pkey, unsigned char **pder);
	//Returns 0 if a key parameter is missing, otherwise 1. It's called by EVP_PKEY_missing_parameters.
    int (*param_missing) (const EVP_PKEY *pk);
	//Copies key parameters from from to to. It MUST return 0 on error, 1 on success. It's called by EVP_PKEY_copy_parameters.
    int (*param_copy) (EVP_PKEY *to, const EVP_PKEY *from);
	//Compares the parameters of keys a and b. It MUST return 1 when the keys are equal, 0 when not equal, or a negative number on error. It's called by EVP_PKEY_cmp_parameters.
    int (*param_cmp) (const EVP_PKEY *a, const EVP_PKEY *b);
	//Prints the private key parameters in humanly readable text to out, indented indent spaces. It MUST return 0 on error, 1 on success. It's called by EVP_PKEY_print_params.
    int (*param_print) (BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx);
	//Prints a signature in humanly readable text to out, indented indent spaces. sigalg contains the exact signature algorithm. If the signature in sig doesn't correspond to what this method expects, X509_signature_dump() must be used as a last resort. It MUST return 0 on error, 1 on success. It's called by X509_signature_print
    int (*sig_print) (BIO *out, const X509_ALGOR *sigalg, const ASN1_STRING *sig, int indent, ASN1_PCTX *pctx);
	//Helps freeing the internals of pkey. It's called by EVP_PKEY_free, EVP_PKEY_set_type, EVP_PKEY_set_type_str, and EVP_PKEY_assign.
	void (*pkey_free) (EVP_PKEY *pkey);
	//Adds extra algorithm specific control. It's called by EVP_PKEY_get_default_digest_nid, EVP_PKEY_set1_tls_encodedpoint, EVP_PKEY_get1_tls_encodedpoint, PKCS7_SIGNER_INFO_set, PKCS7_RECIP_INFO_set, ...
    int (*pkey_ctrl) (EVP_PKEY *pkey, int op, long arg1, void *arg2);
    /* Legacy functions for old PEM */
	//Decode it private key pkey from a DER formatted array. It is exclusively used to help decoding older (pre PKCS#8) PEM formatted encrypted private keys. It MUST return 0 on error, 1 on success. It's called by d2i_PrivateKey.
    int (*old_priv_decode) (EVP_PKEY *pkey, const unsigned char **pder, int derlen);
	//Encode it private key pkey to a DER formatted array. It is exclusively used to help encoding older (pre PKCS#8) PEM formatted encrypted private keys. old_priv_encode() MUST return same kind of values as i2d_PrivateKey(). It's called by i2d_PrivateKey.
    int (*old_priv_encode) (const EVP_PKEY *pkey, unsigned char **pder);
    /* Custom ASN1 signature verification */
	/* The item_sign() and item_verify() methods make it possible to have algorithm specific signatures and verification of them. */
	//item_sign() MUST return one of: 
	//	<=0 error
	// 	1 	item_sign() did everything, OpenSSL internals just needs to pass the signature length back.
	// 	2 	item_sign() did nothing, OpenSSL internal standard routines are expected to continue with the default signature production.
	// 	3 	item_sign() set the algorithm identifier algor1 and algor2, OpenSSL internals should just sign using those algorithms.
	//It's called by ASN1_item_verify, X509_verify, X509_REQ_verify, ...
	int (*item_verify) (EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn, X509_ALGOR *a, ASN1_BIT_STRING *sig, EVP_PKEY *pkey);
	//item_verify() MUST return one of:
	// 	<=0	error
	// 	1 	item_sign() did everything, OpenSSL internals just needs to pass the signature length back.
	// 	2 	item_sign() did nothing, OpenSSL internal standard routines are expected to continue with the default signature production.
	//It's called by  ASN1_item_sign, X509_sign, X509_REQ_sign ...
	int (*item_sign) (EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn, X509_ALGOR *alg1, X509_ALGOR *alg2, ASN1_BIT_STRING *sig);
	//Set custom X509_SIG_INFO parameters. It MUST return 0 on error, or 1 on success. It's called as part of X509_check_purpose, X509_check_ca and X509_check_issued.
	int (*siginf_set) (X509_SIG_INFO *siginf, const X509_ALGOR *alg, const ASN1_STRING *sig);
    /* Check */
	//Check the validity of pk for key-pair. It MUST return 0 for an invalid key, or 1 for a valid key. It's called by EVP_PKEY_check. 
    int (*pkey_check) (const EVP_PKEY *pk);
	//Check the validity of pk for public component. It MUST return 0 for an invalid key, or 1 for a valid key. It's called by EVP_PKEY_public_check. 
    int (*pkey_public_check) (const EVP_PKEY *pk);
	//Check the validity of pk for parameters. It MUST return 0 for an invalid key, or 1 for a valid key. It's called by EVP_PKEY_param_check. 
    int (*pkey_param_check) (const EVP_PKEY *pk);
    /* Get/set raw private/public key data */
	//Set the raw private key for an EVP_PKEY. It MUST return 0 on error, or 1 on success. It's called by EVP_PKEY_new_raw_private_key.
    int (*set_priv_key) (EVP_PKEY *pk, const unsigned char *priv, size_t len);
	//Set the raw public key data for an EVP_PKEY. It MUST return 0 on error, or 1 on success. It's called by EVP_PKEY_new_raw_public_key.
    int (*set_pub_key) (EVP_PKEY *pk, const unsigned char *pub, size_t len);
    int (*get_priv_key) (const EVP_PKEY *pk, unsigned char *priv, size_t *len);
    int (*get_pub_key) (const EVP_PKEY *pk, unsigned char *pub, size_t *len);
} /* EVP_PKEY_ASN1_METHOD */ ;

DEFINE_STACK_OF_CONST(EVP_PKEY_ASN1_METHOD)

extern const EVP_PKEY_ASN1_METHOD cmac_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD dh_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD dhx_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD dsa_asn1_meths[5];
extern const EVP_PKEY_ASN1_METHOD eckey_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD ecx25519_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD ecx448_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD ed25519_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD ed448_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD sm2_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD poly1305_asn1_meth;

extern const EVP_PKEY_ASN1_METHOD hmac_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD rsa_asn1_meths[2];
extern const EVP_PKEY_ASN1_METHOD rsa_pss_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD siphash_asn1_meth;

/*
 * These are used internally in the ASN1_OBJECT to keep track of whether the
 * names and data need to be free()ed
 */
# define ASN1_OBJECT_FLAG_DYNAMIC         0x01/* internal use */
# define ASN1_OBJECT_FLAG_CRITICAL        0x02/* critical x509v3 object id */
# define ASN1_OBJECT_FLAG_DYNAMIC_STRINGS 0x04/* internal use */
# define ASN1_OBJECT_FLAG_DYNAMIC_DATA    0x08/* internal use */
struct asn1_object_st {
    const char *sn, *ln;
    int nid;
    int length;					/* length of data ? */
    const unsigned char *data;  /* data remains const after init */
    int flags;                  /* Should we free this one */
};

/* ASN1 print context structure */

struct asn1_pctx_st {
    unsigned long flags;
    unsigned long nm_flags;
    unsigned long cert_flags;
    unsigned long oid_flags;
    unsigned long str_flags;
} /* ASN1_PCTX */ ;

int asn1_d2i_read_bio(BIO *in, BUF_MEM **pb);
