//
//  GM_AES128_CTR.h
//  CTR-AES
//
//  Created by Gabriel Massana on 18/06/2014.
//  Copyright (c) 2014 Gabriel Massana. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface GM_AES128_CTR : NSObject

+ (NSMutableData*) encryptString: (NSString*) stringToEncrypt withKey: (NSString*) keyString;

+ (NSString*) decryptData: (NSData*) data withKey: (NSString*) keyString;

@end
