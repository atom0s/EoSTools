
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

#ifndef __EOS_H_INCLUDED__
#define __EOS_H_INCLUDED__

#if defined (_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#include <Windows.h>

namespace EoS_Encryption
{
    /**
     * @brief The encryption hash data used by the EoS client.
     */
    const unsigned char EoS_HashData[] = { 0xFF, 0x41, 0x54, 0x73, 0x84, 0x9A, 0xC8, 0xA6 };

    /**
     * @brief The file signature used on encrypted files.
     */
    const unsigned long EoS_FileSignature = 0xD0B7A0CC;

    /**
     * @brief Creates the needed hash objects for the EoS encryption.
     *
     * @param provider          The crypto provider object.
     * @param hash              The crypto hash object.
     * @param key               The crypto key object.
     *
     * @return True on success, false otherwise.
     */
    bool __inline CreateHashObjects(HCRYPTPROV* provider, HCRYPTHASH* hash, HCRYPTKEY* key)
    {
        // Validate the arguments..
        if (provider == nullptr || hash == nullptr || key == nullptr)
            return false;

        HCRYPTPROV hashProvider = NULL;
        HCRYPTHASH hashObject = NULL;
        HCRYPTKEY hashKey = NULL;

        // Obtain the hash context..
        if (!::CryptAcquireContextW(&hashProvider, L"SBENCRYPTIONKEYCONTAINER10", L"Microsoft Enhanced Cryptographic Provider v1.0", 1u, 0))
        {
            if (::GetLastError() != 0x80090016)
                return false;
            if (!::CryptAcquireContextW(&hashProvider, L"SBENCRYPTIONKEYCONTAINER10", nullptr, 1, 8))
                return false;
        }

        // Create the MD5 hash object..
        if (!::CryptCreateHash(hashProvider, CALG_MD5, 0, 0, &hashObject))
        {
            ::CryptReleaseContext(hashProvider, 0);
            return false;
        }

        // Prepare the hash data..
        if (!::CryptHashData(hashObject, (const BYTE*)&EoS_HashData, 8, 0))
        {
            ::CryptDestroyHash(hashObject);
            ::CryptReleaseContext(hashProvider, 0);
            return false;
        }

        // Derive the hash key from our objects..
        if (!::CryptDeriveKey(hashProvider, 0x6801u, hashObject, 0x800000u, &hashKey))
        {
            ::CryptDestroyHash(hashObject);
            ::CryptReleaseContext(hashProvider, 0);
            return 0;
        }

        // Set our output objects..
        *provider = hashProvider;
        *hash = hashObject;
        *key = hashKey;

        return true;
    }

    /**
     * @brief EoS File Decryption Routine
     *
     * @param key               The hash key to decrypt the given data with.
     * @param ptr               Pointer to the data to decrypt.
     *
     * @return Non-used return value.
     */
    int __inline EoS_DecryptData(HCRYPTKEY key, unsigned char* ptr)
    {
        // Decrypt the incoming data..
        auto size = 8;
        ::CryptDecrypt(key, 0, 1, 0, (unsigned char*)ptr, (unsigned long*)&size);

        // Decode the data..
        auto offset = 0;
        auto current = 0;
        auto result = 0;

        do
        {
            // Obtain the current byte of the data..
            current = *(char*)(offset + ptr);

            // Decode the single byte..
            if ((char)current == 127)
                result = 0;
            else if ((char)current == -128)
                result = 255;
            else
            {
                if ((char)current < 0x80u)
                    result = current + 1;
                else
                    result = current - 1;
            }

            // Rewrite the new data..
            *(unsigned char*)(offset++ + ptr) = (unsigned char)result;
        } while (offset < 8);

        // Xor decrypt the data..
        *(unsigned long*)(ptr + 0x00) ^= 0xA4A7FF88;
        *(unsigned long*)(ptr + 0x04) ^= 0xA0447823;

        return result;
    }

    /**
     * @brief EoS File Encryption Routine
     *
     * @param key               The hash key to encrypt the given data with.
     * @param ptr               Pointer to the data to encrypt.
     *
     * @return True if success, false otherwise.
     */
    BOOL __inline EoS_EncryptData(HCRYPTKEY key, unsigned char* ptr)
    {
        *(unsigned long*)(ptr + 0x00) ^= 0xA4A7FF88;
        *(unsigned long*)(ptr + 0x04) ^= 0xA0447823;

        auto offset = 0;
        auto current = (unsigned char)0;
        auto result = (char)0;

        do
        {
            current = *(unsigned char*)(offset + ptr);
            if (current)
            {
                if ((__int8)current == -1)
                    result = -128;
                else if (current >= 0x80)
                    result = current + 1;
                else
                    result = current - 1;
            }
            else
                result = 0x7F;

            *(unsigned char*)(offset++ + ptr) = result;
        } while (offset < 8);

        auto sizeOfData = 8;
        return ::CryptEncrypt(key, 0, 1, 0, (unsigned char*)ptr, (unsigned long*)&sizeOfData, 8);
    }
}; // namespace EoS_Encryption

#endif