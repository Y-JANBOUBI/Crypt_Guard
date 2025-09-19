#include "struct.h"


//================================================================================================//
// Encription
//================================================================================================//
int rc4(char* argv2) {


    // Read payload
    PBYTE Payload = NULL;
    DWORD payloadSize = 0;
    if (!OpenPayloadFile(argv2, &Payload, &payloadSize)) {
        printf("[!] Failed to open payload file: %s\n", argv2);
        return -1;
    }


    // generate keys
    SIZE_T sKeySize = KEY_SIZE;
    BYTE HintByte = NULL;
    PBYTE pOriginalKey = NULL, pProtectedKey = NULL;
    GenerateProtectedKey(sKeySize, &pOriginalKey, &pProtectedKey, &HintByte);
    if (!pOriginalKey || !pProtectedKey, !HintByte) {
        printf("[!] Failed to generate keys\n");
        return -1;
    }



    // encrypted shellcode
    if (!Rc4Encrypt(pOriginalKey, sKeySize, Payload, payloadSize)) {
        printf("[!] Encryption failed\n");
        free(pOriginalKey);
        free(pProtectedKey);
        HeapFree(GetProcessHeap(), 0, Payload);
        return -1;
    }

    // generate output
    generate_RC4_output(Payload, payloadSize, pProtectedKey, sKeySize, HintByte);


    // Cleanup
    free(pOriginalKey);
    free(pProtectedKey);
    HeapFree(GetProcessHeap(), 0, Payload);

}
void aes(char* argv0, char* argv2) {

    PBYTE PlainText = NULL, CipherText = NULL, ProtectedKey = NULL;
    SIZE_T sPlainText = 0, sCipherText = 0;
    BYTE AesKey[KEY_SIZE] = { 0 }, AesIv[IV_SIZE] = { 0 };


    // read payload 
    if (!OpenPayloadFile(argv2, &PlainText, &sPlainText)) {
        printf("[!] Failed to read input file\n");
        return -1;
    }

    // ecrypted payload 
    if (!AesEncryptPayload(PlainText, sPlainText, &CipherText, &sCipherText, AesKey, AesIv)) {
        printf("[!] Encryption failed\n");
        FREE(PlainText);
        return -1;
    }

    // gnerate protect key
    BYTE	bHintByte = (BYTE)(AesKey[0]);
    AESGenerateProtectedKey(AesKey, KEY_SIZE, &ProtectedKey);

    // print payload  
    generate_AES_output(CipherText, sCipherText, ProtectedKey, bHintByte, AesIv, argv0);

    // create heder.h file 
    heder();

    // cleanup 
    FREE(PlainText);
    FREE(CipherText);
    free(ProtectedKey);

}
int xor(char* argv2) {


    // Read payload
    PBYTE Payload = NULL;
    DWORD payloadSize = 0;
    if (!OpenPayloadFile(argv2, &Payload, &payloadSize)) {
        printf("[!] Failed to open payload file: %s\n", argv2);
        return -1;
    }

    // generate keys
    SIZE_T sKeySize = KEY_SIZE;
    BYTE HintByte = NULL;
    PBYTE pOriginalKey = NULL, pProtectedKey = NULL;
    GenerateProtectedKey(sKeySize, &pOriginalKey, &pProtectedKey, &HintByte);
    if (!pOriginalKey || !pProtectedKey, !HintByte) {
        printf("[!] Failed to generate keys\n");
        return -1;
    }

    // encrypted shellcode
    xor_encrypt( Payload, payloadSize, pOriginalKey, sKeySize);

    // generate output
    generate_XOR_output(Payload, payloadSize, pProtectedKey, sKeySize, HintByte);


    // Cleanup
    if(pOriginalKey || pProtectedKey)
        free(pOriginalKey);
        free(pProtectedKey);
    HeapFree(GetProcessHeap(), 0, Payload);

}



int main(int argc, char* argv[]) {

//================================================================================================//
// Get Programe Name
//================================================================================================//
    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
    char fname[_MAX_FNAME];
    char ext[_MAX_EXT];
    _splitpath_s(argv[0], drive, _MAX_DRIVE, dir, _MAX_DIR, fname, _MAX_FNAME, ext, _MAX_EXT);
    char executable_name[_MAX_FNAME + _MAX_EXT];
    strcpy_s(executable_name, _MAX_FNAME + _MAX_EXT, fname);
    strcat_s(executable_name, _MAX_FNAME + _MAX_EXT, ext);

//================================================================================================//
// Usage
//================================================================================================//

    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        print_help(executable_name);
        return 1;
    }

    // Validate initial arguments
    if (argc < 3) {
        print_usage();
        printf("\033[38;2;70;130;180m");
        printf("[!] Invalid arguments\n");
        printf("[?] For help: %s -h or --help\n", executable_name);
        printf("\033[38;5;250m");
        getchar();
        return 1;
    }

//================================================================================================//
// XOR
//================================================================================================//
    if (_stricmp(argv[1], "XOR") == 0 || _stricmp(argv[1], "xor") == 0) {

        if (argc != 3) {
            printf("\033[38;2;70;130;180m");
            printf("[!] Invalid number of arguments for XOR\n");
            printf("[*] Usage: %s XOR <payload_file>\n\n", executable_name);
            printf("\033[38;5;250m");
            return 1;
        }
        xor(argv[2]);

    }

//================================================================================================//
// RC4
//================================================================================================//
    else if (_stricmp(argv[1], "RC4") == 0 || _stricmp(argv[1], "rc4") == 0) {

        if (argc != 3) {
            printf("\033[38;2;70;130;180m");
            printf("\n[!] Invalid number of arguments for RC4\n");
            printf("[*] Usage: %s RC4 <payload_file>\n\n", executable_name);
            printf("\033[38;5;250m");
            return 1;
        }
        rc4(argv[2]);


    }

//================================================================================================//
// AES
//================================================================================================//
    else if (_stricmp(argv[1], "AES") == 0 || _stricmp(argv[1], "aes") == 0) {
        // AES mode: Expect 3 arguments
        if (argc != 3) {
            printf("\033[38;2;70;130;180m");
            printf("[!] Invalid number of arguments for AES\n");
            printf("[*] Usage: %s AES <payload_file>\n\n", executable_name);
            printf("\033[38;5;250m");
            return 1;
        }
        
        aes(executable_name, argv[2]);
         
    }
    else {
        printf("\033[38;2;70;130;180m");
        printf("[!] Invalid encryption type: %s\n", argv[2]);
        printf("[*] Valid types are: XOR, RC4, AES\n\n");
        printf("\033[38;5;250m");
        return 1;
    }

    return 0;
}


