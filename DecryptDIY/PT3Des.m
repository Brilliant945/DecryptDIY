//
//  PT3Des.m
//  PT
//

#import "PT3Des.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation PT3Des

+ (NSData *)encrypt:(NSData *)src key1:(NSString *)key1 key2:(NSString *)key2 key3:(NSString *)key3
{
    if (src == nil || [src length] == 0 ||
        key1 == nil || [key1 length] == 0 ||
        key2 == nil || [key2 length] == 0 ||
        key3 == nil || [key3 length] == 0) {
        
        return nil;
    }
    
    const void *vplainText;
    size_t plainTextBufferSize;
    
    plainTextBufferSize = [src length];
    vplainText = [src bytes];
    
    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    bufferPtrSize = (plainTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    
    bufferPtr = malloc(bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x00, bufferPtrSize);
    
    NSString *key = [NSString stringWithFormat:@"%@%@%@", key1, key2, key3];
    NSString *initVec = @"01234567";
    
    const void *vKey = (const void *)[key UTF8String];
    const void *vinitVec = (const void *)[initVec UTF8String];
    
    uint8_t iv[kCCBlockSize3DES];
    memset((void *)iv, 0x00, (size_t)sizeof(iv));
    
    ccStatus = CCCrypt(kCCEncrypt, kCCAlgorithm3DES, kCCOptionPKCS7Padding | kCCOptionECBMode, vKey, kCCKeySize3DES, vinitVec, vplainText, plainTextBufferSize, (void *)bufferPtr, bufferPtrSize, &movedBytes);
    if (ccStatus != kCCSuccess) {
        free(bufferPtr);
        return nil;
    }
    
    NSData *result = [NSData dataWithBytes:bufferPtr length:movedBytes];
    free(bufferPtr);
    
    return result;
}

+ (NSData *)encryptByBytes:(NSData *)src key1:(NSData *)key1 key2:(NSData *)key2 key3:(NSData *)key3
{
    if (src == nil || [src length] == 0 ||
        key1 == nil || [key1 length] == 0 ||
        key2 == nil || [key2 length] == 0 ||
        key3 == nil || [key3 length] == 0) {
        
        return nil;
    }
    
    const void *vplainText;
    size_t plainTextBufferSize;
    
    plainTextBufferSize = [src length];
    vplainText = [src bytes];
    
    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    bufferPtrSize = (plainTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    
    bufferPtr = malloc(bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x00, bufferPtrSize);
    
    NSMutableData *key = [NSMutableData dataWithData:key1];
    [key appendData:key2];
    [key appendData:key3];
    //    NSData *key = [NSData datawith] [NSString stringWithFormat:@"%@%@%@", key1, key2, key3];
    NSString *initVec = @"01234567";
    
    const void *vKey = (const void *)[key bytes];
    const void *vinitVec = (const void *)[initVec UTF8String];
    
    uint8_t iv[kCCBlockSize3DES];
    memset((void *)iv, 0x00, (size_t)sizeof(iv));
    
    ccStatus = CCCrypt(kCCEncrypt, kCCAlgorithm3DES, kCCOptionPKCS7Padding | kCCOptionECBMode, vKey, kCCKeySize3DES, vinitVec, vplainText, plainTextBufferSize, (void *)bufferPtr, bufferPtrSize, &movedBytes);
    if (ccStatus != kCCSuccess) {
        free(bufferPtr);
        return nil;
    }
    
    NSData *result = [NSData dataWithBytes:bufferPtr length:movedBytes];
    free(bufferPtr);
    
    return result;
}

+ (NSData *)decrypt:(NSData *)src key1:(NSString *)key1 key2:(NSString *)key2 key3:(NSString *)key3
{
    if (src == nil || [src length] == 0 ||
        key1 == nil || [key1 length] == 0 ||
        key2 == nil || [key2 length] == 0 ||
        key3 == nil || [key3 length] == 0) {
        
        return nil;
    }
    
    const void *vplainText;
    size_t plainTextBufferSize;
    
    plainTextBufferSize = [src length];
    vplainText = [src bytes];
    
    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    
    bufferPtrSize = (plainTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    bufferPtr = malloc(bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x00, bufferPtrSize);
    
    NSString *key = [NSString stringWithFormat:@"%@%@%@", key1, key2, key3];
    NSString *initVec = @"01234567";
    
    const void *vkey = (const void *)[key UTF8String];
    const void *vinitVec = (const void *)[initVec UTF8String];
    
    uint8_t iv[kCCBlockSize3DES];
    memset((void *)iv, 0x00, (size_t)sizeof(iv));
    
    ccStatus = CCCrypt(kCCDecrypt, kCCAlgorithm3DES, kCCOptionPKCS7Padding | kCCOptionECBMode, vkey, kCCKeySize3DES, vinitVec, vplainText, plainTextBufferSize, (void *)bufferPtr, bufferPtrSize, &movedBytes);
    if (ccStatus != kCCSuccess) {
        free(bufferPtr);
        return nil;
    }
    
    NSData *result = [NSData dataWithBytes:bufferPtr length:movedBytes];
    free(bufferPtr);
    
    return result;
}

+ (NSData *)decryptByBytes:(NSData *)src key1:(NSData *)key1 key2:(NSData *)key2 key3:(NSData *)key3
{
    if (src == nil || [src length] == 0 ||
        key1 == nil || [key1 length] == 0 ||
        key2 == nil || [key2 length] == 0 ||
        key3 == nil || [key3 length] == 0) {
        
        return nil;
    }
    
    const void *vplainText;
    size_t plainTextBufferSize;
    
    plainTextBufferSize = [src length];
    vplainText = [src bytes];
    
    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    
    bufferPtrSize = (plainTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    bufferPtr = malloc(bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x00, bufferPtrSize);
    
    NSMutableData *key = [NSMutableData dataWithData:key1];
    [key appendData:key2];
    [key appendData:key3];
    //    NSString *key = [NSString stringWithFormat:@"%@%@%@", key1, key2, key3];
    NSString *initVec = @"01234567";
    
    const void *vkey = (const void *)[key bytes];
    const void *vinitVec = (const void *)[initVec UTF8String];
    
    uint8_t iv[kCCBlockSize3DES];
    memset((void *)iv, 0x00, (size_t)sizeof(iv));
    
    ccStatus = CCCrypt(kCCDecrypt, kCCAlgorithm3DES, kCCOptionPKCS7Padding | kCCOptionECBMode, vkey, kCCKeySize3DES, vinitVec, vplainText, plainTextBufferSize, (void *)bufferPtr, bufferPtrSize, &movedBytes);
    if (ccStatus != kCCSuccess) {
        free(bufferPtr);
        return nil;
    }
    
    NSData *result = [NSData dataWithBytes:bufferPtr length:movedBytes];
    free(bufferPtr);
    
    return result;
}

+ (bool)encryptWriteFile:(NSString *)filePath encryptData:(NSData *)src key1:(NSString *)key1 key2:(NSString *)key2 key3:(NSString *)key3{
    
    NSData *encryptData = [PT3Des encrypt:src key1:key1 key2:key2 key3:key3];
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if ([fileManager fileExistsAtPath:filePath]) {
        [fileManager removeItemAtPath:filePath error:nil];
    }
    return [fileManager createFileAtPath:filePath contents:encryptData attributes:nil];
}

+ (NSData *)decryptReadFile:(NSString *)filePath key1:(NSString *)key1 key2:(NSString *)key2 key3:(NSString *)key3{
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:filePath]) {
        return nil;
    }
    NSData *data = [NSData dataWithContentsOfFile:filePath];
    
    return [PT3Des decrypt:data key1:key1 key2:key2 key3:key3];
}

@end
