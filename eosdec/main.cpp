
/**
* The Atomic License v1
*
* Copyright (c) 2015, atom0s [atom0s@live.com]
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
*    (1) Redistributions of binary form must reproduce the above copyright notice,
*        this list of conditions and following disclaimer.
*    (2) Redistributions of source code must retain the above copyright notice,
*        this list of conditions and following disclaimer.
*    (3) Redistributions of source code must not be modified.
*    (4) This software and associated works may not be used for any commericial purposes.
*    (5) Recreations, adaptations, and any and all usage of this software and its associated
*        works must be available, open source, to all whom request it.
*
*    (6) You agree that this license can change, at any time, without warning.
*
* You agree that the original creator of this software and associated works, atom0s, has full
* permission to use this work and associated works for commericial purposes.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#pragma comment(lib, "Shlwapi.lib")

#include <Windows.h>
#include <Shlwapi.h>
#include <string>
#include "../Common/EoS.h"

/**
 * @brief Application entry point.
 *
 * @param argc          The number of arguments passed to this application.
 * @param argv          The array of arguments.
 *
 * @return Non-important return value.
 */
int __cdecl main(int argc, char* argv[])
{
    printf_s("Echo of Soul - File Decryption Tool\r\n");
    printf_s("(c) 2015 atom0s [atom0s@live.com]\r\n");

    // File decryption function..
    auto decrypt = [&](const std::string& filePath) -> bool
    {
        printf_s("\r\n[*] INFO : Processing file: %s\r\n", ::PathFindFileName(filePath.c_str()));

        // Ensure the file does not exist..
        if (::GetFileAttributes(filePath.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            printf_s("[*] ERROR: File does not exist; cannot decrypt!\r\n");
            return false;
        }

        // Obtain the files directory..
        char fileDirectory[MAX_PATH] = { 0 };
        strcpy_s(fileDirectory, filePath.c_str());
        ::PathRemoveFileSpec(fileDirectory);

        // Set the files working directory..
        if (strlen(fileDirectory) > 0)
            ::SetCurrentDirectory(fileDirectory);

        // Open the file for reading..
        FILE* f = nullptr;
        if (fopen_s(&f, filePath.c_str(), "rb") != ERROR_SUCCESS)
        {
            printf_s("[*] ERROR: Failed to open file for reading; cannot decrypt!\r\n");
            return false;
        }

        // Obtain the file size..
        fseek(f, 0, SEEK_END);
        auto size = ftell(f);
        fseek(f, 0, SEEK_SET);

        // Read the file data..
        auto data = new unsigned char[size + 1];
        fread(data, size, 1, f);
        fclose(f);

        // Ensure the file is protected..
        if (*(unsigned long*)data != EoS_Encryption::EoS_FileSignature)
        {
            delete[] data;
            printf_s("[*] ERROR: File does not have proper signature; cannot decrypt!\r\n");
            return false;
        }

        HCRYPTPROV provider = NULL;
        HCRYPTHASH hash = NULL;
        HCRYPTKEY key = NULL;

        // Obtain the required hash provider data..
        if (!EoS_Encryption::CreateHashObjects(&provider, &hash, &key))
        {
            delete[] data;
            printf_s("[*] ERROR: Could not obtain required hash data; cannot decrypt!\r\n");
            return false;
        }

        // Divide the size into blocks (8 bytes)..
        auto sizeLeft = (size - 4) >> 3;
        auto dataPtr = (unsigned char*)data;

        // Skip the signature data..
        dataPtr += 4;

        do
        {
            EoS_Encryption::EoS_DecryptData(key, dataPtr);
            dataPtr += 8;
            --sizeLeft;
        } while (sizeLeft);

        // Write the decrypted data to a new decrypted file..
        auto str = filePath + ".dec";
        if (fopen_s(&f, str.c_str(), "wb") == ERROR_SUCCESS)
        {
            fwrite(data + 4, size - 4, 1, f);
            fclose(f);

            printf_s("[*] INFO : Success! File dumped.\r\n");
        }
        else
            printf_s("[*] ERROR: Could not write decrypted file!\r\n");

        delete[] data;
        return true;
    };

    // Ensure we were passed arguments..
    if (argc <= 1)
    {
        printf_s("[*] ERROR: Invalid usage!\r\n");
        printf_s("[*] ERROR: Usage: eosdec.exe [file] [file] [file]\r\n");
        return 0;
    }

    // Process each file..
    for (auto x = 1; x < argc; x++)
        decrypt(argv[x]);

    return ERROR_SUCCESS;
}