#define __STDC_WANT_LIB_EXT1__ 1
#include <array>
#include <iostream>
#include <cstring>
#include <vector>

#include <sodium.h>
#include "cipher.h"

/***********************************************

The Cipher class allows you to:

* Encrypt and decrypt messages
* Protect the integrity of unencrypted data

You can let the class generate a key, or use it
with your own key.

The former case is recommended.

For the latter case read on:

Itt is the responsability of the caller to get
rid of the key after instantiating the cipher.
It is also the responsability of the caller not
to provide a nonce that is smaller than any 
nonce used in the past.

Nonces start at 1 and get incremented for each
message to be encrypted. It is important not to
repeat these values.

This means that there are two good cases to use
this constructor with your own key and cipher:

* You have never used that key before.
* You have used that key before. Then you should
make sure that the previous Cipher instance has 
been destroyed. The nonce to be used must be the
last nonce used by the previous Cipher instance.

***********************************************/

/*
key: std::array<uint8_t, 32>
nonce: std::array<uint8_t, 12>
*/
Cipher::Cipher(const chacha20_key_t& k, const nonce_t& n) {
	// copying key
	key = k;
	nonce = n;
};

Cipher::Cipher(){
	// random key
	randombytes_buf(key.data(), key.size());

	// nonce set to 0
	std::fill(nonce.begin(), nonce.end(), 0);
}

Cipher::~Cipher(){
	memset_s(key.data(), key.size(), 0, key.size());
}

// encrypt
// it should verify the data is < to some limit (nonce)
// and that the nonce is not wrapping around
ciphertext_t Cipher::encrypt(const std::string& plaintext,
										 const std::string& ad,
										 nonce_t& nonce_ret){

	sodium_increment(nonce.data(), nonce.size());
	nonce_ret = nonce;

	// test for wrap around
	uint8_t mask = 0;
	for(auto &i : nonce)
		mask |= i;
	if(mask == 0){
		throw std::exception();
	}

	//
	unsigned char* ciphertext_c = new unsigned char[plaintext.length() + crypto_aead_chacha20poly1305_IETF_ABYTES];
	unsigned long long ciphertext_len;

	if (crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext_c,
																							(unsigned long long*) &ciphertext_len, 
																							(unsigned char*) plaintext.data(),
																							(unsigned long long) plaintext.length(),
																							(unsigned char*) ad.data(),
																							(unsigned long long) ad.length(),
																								NULL, nonce.data(), key.data()) != 0) {
		throw std::exception();
	}

	ciphertext_t ciphertext(ciphertext_c, ciphertext_c + ciphertext_len);
	delete[] ciphertext_c;

	return ciphertext;
}

// decrypt
std::string Cipher::decrypt(const ciphertext_t& ciphertext,
										 const std::string& ad,
										 const nonce_t& nonce){

	unsigned char* decrypted_c = new unsigned char[ciphertext.size()];
	unsigned long long decrypted_len;

	if (crypto_aead_chacha20poly1305_ietf_decrypt(decrypted_c,
																								(unsigned long long*) &decrypted_len,
																								NULL,
																								ciphertext.data(),
																								(unsigned long long) ciphertext.size(),
																								(unsigned char*) ad.data(),
																								(unsigned long long) ad.length(),
																								nonce.data(), key.data()) != 0) {
		throw std::exception();
	}

	std::string decrypted(decrypted_c, decrypted_c + decrypted_len);
	delete[] decrypted_c;

	return decrypted;
}
