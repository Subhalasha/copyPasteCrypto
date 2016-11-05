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
	// Instanciate the cipher
	//

	Cipher box;

	while(true){

		// PLAINTEXT
		string plaintext;
		cout << "message to encrypt: ";
		cin >> plaintext;

		// AD
		string ad;
		cout << "additional data to authenticate: ";
		cin >> ad;

		// Encryption test
		nonce_t nonce;
		ciphertext_t ciphertext;

		try{
			ciphertext = box.encrypt(plaintext, ad, nonce);
		}
		catch(...){
			cout << "Can't encrypt";
			return 1;
		}

		cout << "ciphertext:" << endl;
		for(const auto& i : ciphertext){
			printf("%02x", i);
		}

		cout << endl << "nonce:" << endl;
		for(const auto& i : nonce){
			printf("%02x", i);
		}

		// Decryption test
		string decrypted;

		try{
			decrypted = box.decrypt(ciphertext, ad, nonce);
		}
		catch(...){
			cout << endl << "Can't decrypt. Ciphertext or Additional Data has been modified";
			return 1;
		}

		cout << endl << "plaintext: " << decrypted << endl;
	}

	return 0;
}
