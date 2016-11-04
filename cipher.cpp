#include <array>
#include <iostream>
#include <cstring>
#include <vector>

#include <sodium.h>
#include "cipher.h"

// constructor 1
Cipher::Cipher(const chacha20_key_t& k) {
	// copying key
	key = k;

	// nonce set to 0
	std::fill(nonce.begin(), nonce.end(), 0);
	
	// should this program get rid of the initial key?
	// -> the responsability of the caller
	// std::fill(k.begin(), k.end(), 0);
};

// constructor 2
Cipher::Cipher(){
	// random key
	generate_key();

	// nonce set to 0
	std::fill(nonce.begin(), nonce.end(), 0);
}

Cipher::~Cipher(){
	std::fill(key.begin(), key.end(), 0); // memset_s instead?
}

// returns a key
void Cipher::generate_key(){
	randombytes_buf(key.data(), key.size());
}

// encrypt
// it should verify the data is < to some limit (nonce)
ciphertext_t Cipher::encrypt(const std::string& plaintext,
										 const std::string& ad,
										 nonce_t& nonce_ret){

	sodium_increment(nonce.data(), nonce.size());
	nonce_ret = nonce;

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
