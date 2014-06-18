//
//  GM_AES128_CTR.m
//  CTR-AES
//
//  Created by Gabriel Massana on 18/06/2014.
//  Copyright (c) 2014 Gabriel Massana. All rights reserved.
//

#import "GM_AES128_CTR.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <Security/Security.h>

//Remember to import Security


@implementation GM_AES128_CTR


+ (NSMutableData*) encryptString: (NSString*) stringToEncrypt withKey: (NSString*) keyString
{
    //Key to Data
    NSData *key = [keyString dataUsingEncoding:NSUTF8StringEncoding];
    
    //String to encrypt to Data
    NSData *data = [stringToEncrypt dataUsingEncoding:NSUTF8StringEncoding];
    
    // Init cryptor
    CCCryptorRef cryptor = NULL;
    
    // Alloc Data Out
    NSMutableData *cipherData = [NSMutableData dataWithLength:data.length + kCCBlockSizeAES128];
    
    //Empty IV: initialization vector
    NSMutableData *iv =  [NSMutableData dataWithLength:kCCBlockSizeAES128];
    
    //Create Cryptor
    CCCryptorStatus  create = CCCryptorCreateWithMode(kCCEncrypt,
                                                      kCCModeCTR,
                                                      kCCAlgorithmAES,
                                                      ccPKCS7Padding,
                                                      iv.bytes, // can be NULL, because null is full of zeros
                                                      key.bytes,
                                                      key.length,
                                                      NULL,
                                                      0,
                                                      0,
                                                      kCCModeOptionCTR_BE,
                                                      &cryptor);
    
    if (create == kCCSuccess)
    {
        //alloc number of bytes written to data Out
        size_t outLength;
        
        //Update Cryptor
        CCCryptorStatus  update = CCCryptorUpdate(cryptor,
                                                  data.bytes,
                                                  data.length,
                                                  cipherData.mutableBytes,
                                                  cipherData.length,
                                                  &outLength);
        if (update == kCCSuccess)
        {
            //Cut Data Out with nedded length
            cipherData.length = outLength;
            
            //Final Cryptor
            CCCryptorStatus final = CCCryptorFinal(cryptor, //CCCryptorRef cryptorRef,
                                                   cipherData.mutableBytes, //void *dataOut,
                                                   cipherData.length, // size_t dataOutAvailable,
                                                   &outLength); // size_t *dataOutMoved)
            
            if (final == kCCSuccess)
            {
                //Release Cryptor
                //CCCryptorStatus release =
                CCCryptorRelease(cryptor ); //CCCryptorRef cryptorRef
            }
            return cipherData;
            
        }
        
        
        
    }
    else
    {
        //error
        
    }
    
    return nil;
}



+ (NSString*) decryptData: (NSData*) data withKey: (NSString*) keyString
{
    //Key to Data
    NSData *key = [keyString dataUsingEncoding:NSUTF8StringEncoding];
    
    // Init cryptor
    CCCryptorRef cryptor = NULL;
    
    //Empty IV: initialization vector
    NSMutableData *iv =  [NSMutableData dataWithLength:kCCBlockSizeAES128];
    
    // Create Cryptor
    CCCryptorStatus createDecrypt = CCCryptorCreateWithMode(kCCDecrypt, // operation
                                                            kCCModeCTR, // mode CTR
                                                            kCCAlgorithmAES, // Algorithm
                                                            ccPKCS7Padding, // padding
                                                            iv.bytes, // can be NULL, because null is full of zeros
                                                            key.bytes, // key
                                                            key.length, // keylength
                                                            NULL, //const void *tweak
                                                            0, //size_t tweakLength,
                                                            0, //int numRounds,
                                                            kCCModeOptionCTR_BE, //CCModeOptions options,
                                                            &cryptor); //CCCryptorRef *cryptorRef
    
    
    if (createDecrypt == kCCSuccess)
    {
        // Alloc Data Out
        NSMutableData *cipherDataDecrypt = [NSMutableData dataWithLength:data.length + kCCBlockSizeAES128];
        
        //alloc number of bytes written to data Out
        size_t outLengthDecrypt;
        
        //Update Cryptor
        CCCryptorStatus updateDecrypt = CCCryptorUpdate(cryptor,
                                                        data.bytes, //const void *dataIn,
                                                        data.length,  //size_t dataInLength,
                                                        cipherDataDecrypt.mutableBytes, //void *dataOut,
                                                        cipherDataDecrypt.length, // size_t dataOutAvailable,
                                                        &outLengthDecrypt); // size_t *dataOutMoved)
        
        if (updateDecrypt == kCCSuccess)
        {
            //Cut Data Out with nedded length
            cipherDataDecrypt.length = outLengthDecrypt;
            
            // Data to String
            NSString* cipherFinalDecrypt = [[NSString alloc] initWithData:cipherDataDecrypt encoding:NSUTF8StringEncoding];
            
            //Final Cryptor
            CCCryptorStatus final = CCCryptorFinal(cryptor, //CCCryptorRef cryptorRef,
                                                   cipherDataDecrypt.mutableBytes, //void *dataOut,
                                                   cipherDataDecrypt.length, // size_t dataOutAvailable,
                                                   &outLengthDecrypt); // size_t *dataOutMoved)
            
            if (final == kCCSuccess)
            {
                //Release Cryptor
                //CCCryptorStatus release =
                CCCryptorRelease(cryptor); //CCCryptorRef cryptorRef
            }
            
            return cipherFinalDecrypt;
        }
    }
    
    return nil;
}

@end
