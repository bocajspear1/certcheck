// CertCheck.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <Wincrypt.h>
#include <cryptuiapi.h>
#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <list>
#include <atlstr.h>


#define NAMELEN 128

using namespace std;

typedef struct cert_check_item {
	string type;
	string size;
	string expires;
	string thumbprint;
} cert_check_item;

void print_error(string message);

int _tmain(int argc, _TCHAR* argv[])
{

	cout << "CertCheck v1.0\nBy Jacob Hartman\n----------------------------------------------------------" << endl;

	cout << "\nCaching valid root certificates..." << endl;

	// Load the thumbprint file
	string line;
	ifstream thumbprint_file("./thumbprints.txt");
	list<cert_check_item> check_list;


	if (thumbprint_file.is_open())
	{
		while (getline(thumbprint_file, line))
		{

			string temp = "";

			cert_check_item * temp_item = new cert_check_item();
			int section_start = line.find_last_of(' ') + 1;
			temp_item->thumbprint = line.substr(section_start);
			temp = line.substr(0, section_start - 1);

			section_start = temp.find_last_of(' ') + 1;
			temp_item->expires = temp.substr(section_start);
			temp = temp.substr(0, section_start - 1);

			section_start = temp.find_last_of(' ') + 1;
			temp_item->size = temp.substr(section_start);
			temp_item->type = temp.substr(0, section_start - 1);

			check_list.push_back(*temp_item);

		}
		thumbprint_file.close();
	}
	else {
		print_error("Could not open thumbprints file");
		exit(1);
	}


	HCERTSTORE system_store = CertOpenSystemStore(NULL, L"Root");
	PCCERT_CONTEXT  cert_context = NULL;
	DWORD property_id = 0;
	DWORD data_pointer;
	void * data_item;

	int invalid_count = 0;

	cout << "\nOpening certificate store..." << endl;

	if (system_store)
	{
		cout << "Successfully opened the certificate store\n" << endl;

		cout << "=============================================" << endl;

		while (cert_context = CertEnumCertificatesInStore(system_store, cert_context))
		{
			if (cert_context)
			{
				
				char subject_name[129] = "";

				if (CertGetNameStringA(cert_context, CERT_NAME_FRIENDLY_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, subject_name, NAMELEN))
				{
					cout << "Certificate Name: " << subject_name << endl;

					// Get the certificate's thumbprint
					DWORD thumbprint_size = 20;
					BYTE thumbprint[20];
					string hash_string;

					if (CryptHashCertificate(NULL, 0, 0, cert_context->pbCertEncoded, cert_context->cbCertEncoded, thumbprint, &thumbprint_size))
					{
						// Convert the thumbprint to a hex string
						stringstream convert;

						convert << hex << std::setfill('0');

						for (int i = 0; i < 20; i++)
						{
							convert << setw(2) << (int)thumbprint[i];
						}
						string final_hash = convert.str();
						transform(final_hash.begin(), final_hash.end(), final_hash.begin(), toupper);

						cout << "Thumbprint: " << final_hash << endl;

						// Check if the thumbprint is in the list
						bool is_valid = false;
						cert_check_item futher_verify;


						list<cert_check_item>::const_iterator iterator;
						for (iterator = check_list.begin(); iterator != check_list.end(); ++iterator) {
							if (iterator->thumbprint == final_hash)
							{
								is_valid = true;
								futher_verify = *iterator;
							}
						}

						if (is_valid == true)
						{
							//CERT_SIGN_HASH_CNG_ALG_PROP_ID
							cout << "Thumbprint Verification: PASSED" << endl;

						//	while (property_id = CertEnumCertificateContextProperties(cert_context, property_id))
						//	{

						//		cout << "\nProperty ID: " << property_id << endl;


						//		if (CertGetCertificateContextProperty(cert_context, property_id, NULL, &data_pointer))
						//		{
						//			if (data_item = (void*)malloc(data_pointer))
						//			{
						//				if (CertGetCertificateContextProperty(cert_context, property_id, data_item, &data_pointer))
						//				{
						//					if (property_id == CERT_SIGN_HASH_CNG_ALG_PROP_ID)
						//					{
						//						wstring raw_type = (LPWSTR)data_item;
						//						
						//						int loc = raw_type.find_first_of('/');

						//						wstring type = raw_type.substr(0, loc);



						//						if ((type == L"RSA" && futher_verify.type == "RSA") || 
						//							(type == L"ECDSA" && futher_verify.type == "ECC"))
						//						{
						//							cout << "Algorithm Verification: PASSED" << endl;
						//						}
						//						else {
						//							cout << "WARNING: Algorithm Verification failed!" << endl;
						//						}

						//					}



						//					free(data_item);
						//				}
						//				else {


						//				}

						//			}
						//			else {


						//			}
						//		}
						//		else
						//		{

						//		}

						//	}
						}else {
							cout << "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n!\n! WARNING: Certificate not in list of valid root certificates!\n!\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << endl;
							invalid_count += 1;
						}
						

					} else {
						print_error("Getting certificate hash failed");
					}
				

					
					getchar();
				}
				else
				{
					print_error("Getting certificate name failed");
				}
					


			}
			else
			{
				print_error("Could not open certificate");
			}
		}
		cout << "Check Complete, Press <Enter> to exit." << endl;
		if (invalid_count > 0)
		{
			cout << invalid_count << " certificates were found to be invalid." << endl;
		}
		getchar();
	}
	else {
		print_error("Error opening CertStore");
		exit(1);
	}

	return 0;
}

void print_error(string message)
{
	cout << "ERROR: " << message << endl;
	getchar();
}