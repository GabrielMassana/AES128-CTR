//
//  ViewController.m
//  CTR-AES
//
//  Created by Gabriel Massana on 18/06/2014.
//  Copyright (c) 2014 Gabriel Massana. All rights reserved.
//

#import "ViewController.h"

#import "GM_AES128_CTR.h"

@interface ViewController ()

@end


@implementation ViewController

- (void)viewDidLoad
{
    [super viewDidLoad];

    NSString *key = @"1234567890ABCDEFGHIJKLMNOPQRSTUV";
    NSString *stringToEncrypt = @"Gabriel.Massana";
    NSLog(@"   to encrypt ------> %@", stringToEncrypt);
    
    NSData* encrypted = [GM_AES128_CTR encryptString:stringToEncrypt withKey:key];
    
    NSLog(@"   encrypted DATA --> %@", encrypted);
    
    NSString *decrypted = [GM_AES128_CTR decryptData:encrypted withKey:key];
    
    NSLog(@"   decrypted -------> %@", decrypted);
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
