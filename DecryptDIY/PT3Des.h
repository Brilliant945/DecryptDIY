//
//  PT3Des.h
//  PT
//

#import <Foundation/Foundation.h>

/**
 @ingroup encryptionDecryptModuleClass
 * 3DES加密算法,请保证密钥长度是8
 */
@interface PT3Des : NSObject

/**
 * 3DES解密
 * @param  src   解密前的密文
 * @param  key1  密钥1
 * @param  key2  密钥2
 * @param  key3  密钥3
 * @return 解密后的明文
 */
+ (NSData *)decrypt:(NSData *)src key1:(NSString *)key1 key2:(NSString *)key2 key3:(NSString *)key3;
+ (NSData *)decryptByBytes:(NSData *)src key1:(NSData *)key1 key2:(NSData *)key2 key3:(NSData *)key3;

/**
 * 3DES加密
 * @param  src   加密前的明文
 * @param  key1  密钥1
 * @param  key2  密钥2
 * @param  key3  密钥3
 * @return  加密后的密文
 * licence 秘钥
 */
+ (NSData *)encrypt:(NSData *)src key1:(NSString *)key1 key2:(NSString *)key2 key3:(NSString *)key3;

/**
 *  对数据加密写入本地
 *
 *  @param filePath 写入文件路径
 *  @param src      写入数据
 *  @param key1     密钥1
 *  @param key2     密钥2
 *  @param key3     密钥3
 *
 *  @return 写入结果 成功与否
 */
+ (bool)encryptWriteFile:(NSString *)filePath encryptData:(NSData *)src key1:(NSString *)key1 key2:(NSString *)key2 key3:(NSString *)key3;

/**
 *  读取本地加密文件
 *
 *  @param filePath 文件路径
 *  @param key1     密钥1
 *  @param key2     密钥2
 *  @param key3     密钥3
 *
 *  @return 解密后文件数据
 */
+ (NSData *)decryptReadFile:(NSString *)filePath key1:(NSString *)key1 key2:(NSString *)key2 key3:(NSString *)key3;

@end
