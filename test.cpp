#include <sodium.h>

#include <array>
#include <iostream>
#include <cstring>
#include <vector>

#include "cipher.h"

int main()
{
	using namespace	std;

	//
	// Init libsodium
	//
	if (sodium_init() == -1) {
		cout << "can't init libsodium";
		return 1;
	}

	//
	// Test 1: correct plaintext
	//
	Cipher* box;

	box = new Cipher();

	string plaintext("Hello, this is a test, a really good one");
	string ad("Hello, this is a test, a really good two");

	nonce_t nonce;
	ciphertext_t ciphertext;

	try{
		ciphertext = box->encrypt(plaintext, ad, nonce);
	}
	catch(...){
		cout << endl << "Test 1: Can't encrypt" << endl;
		return 1;
	}

	string decrypted;

	try{
		decrypted = box->decrypt(ciphertext, ad, nonce);
	}
	catch(...){
		cout << endl << "Test 1: Can't decrypt" << endl;
		return 1;
	}

	if(plaintext.compare(decrypted) != 0){
		cout << endl << "Test 1: Wrong decryption" << endl;
		return 1;
	}

	delete box;

	//
	// Test 2: constructor 2
	//

	chacha20_key_t key;
	randombytes_buf(key.data(), key.size());
	box = new Cipher(key, nonce);

	ciphertext_t ciphertext2;

	try{
		ciphertext2 = box->encrypt(plaintext, ad, nonce);
	}
	catch(...){
		cout << endl << "Test 2: Can't encrypt" << endl;
		return 1;
	}

	delete box;


	box = new Cipher(key, nonce);

	string decrypted2;

	try{
		decrypted2 = box->decrypt(ciphertext2, ad, nonce);
	}
	catch(...){
		cout << endl << "Test 2: Can't decrypt" << endl;
		return 1;
	}

	if(plaintext.compare(decrypted2) != 0){
		cout << endl << "Test 2: Wrong decryption" << endl;
		return 1;
	}

	delete box;


	//
	// Test 3: Wrong Additional Data
	//

	box = new Cipher(key, nonce);
	
	bool thrown = false;
	
	string ad2("this was modified");

	try{
		box->decrypt(ciphertext2, ad2, nonce);
	}
	catch(...){
		thrown = true;
	}

	if(!thrown){
		cout << endl << "Test 3: should have thrown" << endl;
		return 1;
	}

	delete box;

	//
	// Test 4: Wrong Ciphertext
	//

	box = new Cipher(key, nonce);
	
	ciphertext2[0] = ~ciphertext2[0];

	thrown = false;
	
	try{
		box->decrypt(ciphertext2, ad, nonce);
	}
	catch(...){
		thrown = true;
	}

	if(!thrown){
		cout << endl << "Test 4: should have thrown" << endl;
		return 1;
	}

	delete box;

	//
	// Test 5: Nonce wrap around
	//

	std::fill(nonce.begin(), nonce.end(), 0xff);

	box = new Cipher(key, nonce);

	thrown = false;
	
	try{
		box->encrypt(plaintext, ad, nonce);
	}
	catch(...){
		thrown = true;
	}

	if(!thrown){
		cout << endl << "Test 5: should have thrown" << endl;
		return 1;
	}

	delete box;

	cout << "All tests passed!";
	return 0;
}
