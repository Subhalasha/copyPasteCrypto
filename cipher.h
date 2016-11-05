#pragma once

#include <array>
#include <iostream>
#include <vector>
#include <string>

#include <sodium.h>

using	nonce_t = std::array<uint8_t, crypto_aead_chacha20poly1305_IETF_NPUBBYTES>;
using chacha20_key_t = std::array<uint8_t, crypto_aead_chacha20poly1305_IETF_KEYBYTES>;
using ciphertext_t = std::vector<uint8_t>;

class Cipher {

	chacha20_key_t key;
	nonce_t nonce;

public:

	// constructor
	Cipher(const chacha20_key_t &k, const nonce_t &n);
	Cipher();
	~Cipher();

	// encrypt
	ciphertext_t encrypt(const std::string& plaintext, const std::string& ad, nonce_t& nonce);

	// decrypt
	std::string decrypt(const ciphertext_t& ciphertext,
							 const std::string& ad,
							 const nonce_t& nonce);

	// end of class
};
