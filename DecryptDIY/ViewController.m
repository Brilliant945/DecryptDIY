//
//  ViewController.m
//  DecryptDIY
//
//  Created by 肖瑞 on 17/6/15.
//  Copyright © 2017年 肖瑞. All rights reserved.
//

#import "ViewController.h"
#import "PT3Des.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [self fileManager];  // 给文件做加解密处理
}


#pragma mark - 给文件做加解密处理
/**
 操作说明：
 1.把要处理的文件放在Mac家目录下面；
 2.在家目录下创建decrypt和encrypt两个文件夹，分别用于保存解密后或加密后的文件；
 3.更新文件名的初始化和Mac家目录，Xcode连接模拟器（不要连接真机），run工程；
 */
- (void)fileManager
{
    // 初始化文件名
    NSString *fileName = @"shiqingquan_20180225_763B0675CC58465.log";
    
    // 创建Mac家目录
    NSString *homePath = @"/Users/xiao";
    // 获取文件路径
    NSString *filePath = [homePath stringByAppendingPathComponent:fileName];
    // 获取文件，转成NSData格式
    NSData *data = [NSData dataWithContentsOfFile:filePath];
    
#if 1
    
    // 给文件解密，保存到"/Users/xiaorui/decrypt"文件夹
    NSData * decryptData= [self decryptData:data withFileName:fileName];
    NSString *decryptPath = [homePath stringByAppendingString:[NSString stringWithFormat:@"/decrypt/%@",fileName]];
    BOOL res = [decryptData writeToFile:decryptPath atomically:YES];
    if (res) {
        NSLog(@"文件解密成功！");
    }
    
#else
    
    // 给文件加密，保存到"/Users/xiaorui/encrypt"文件夹
    NSData * encryptData= [self encryptData:data withFileName:fileName];
    NSString *encryptPath = [homePath stringByAppendingString:[NSString stringWithFormat:@"/encrypt/%@",fileName]];
    BOOL res = [encryptData writeToFile:encryptPath atomically:YES];
    if (res) {
        NSLog(@"文件加密成功！");
    }
    
#endif    
    
}


#pragma mark - 解密方法
// 注意：未经加密的文件，不能使用此解密方法，否则可能导致文件无法打开
- (NSData *)decryptData:(NSData *)data withFileName:(NSString *)fileName
{
    // 获取设备号前15位
    NSArray *arr = [fileName componentsSeparatedByString:@"_"];
    NSString *UUID = [arr[2] stringByReplacingOccurrencesOfString:@".log" withString:@""];
    
//    NSString *UUID = @"4A9C88D643344B4";
    
    int config[] = {33, 22, 88, 44, 77, 66};
    NSMutableString *buffer = [NSMutableString string];
    int start = 0;
    int end = 0;
    
    for (int i = 0; i < 3; i++) {
        start = config[i * 2] % UUID.length;
        end = config[i * 2 + 1] % UUID.length;
        if (start > end) {
            start ^= end;
            end ^= start;
            start ^= end;
        }
        [buffer appendString:[UUID substringWithRange:NSMakeRange(start, end - start)]];
    }
    
    while (buffer.length < 24) {
        [buffer appendString:@"0"];
    }
    NSString *enKey = [UUID stringByAppendingString:buffer];
    NSString *key1 = [enKey substringWithRange:NSMakeRange(0, 8)];
    NSString *key2 = [enKey substringWithRange:NSMakeRange(8, 8)];
    NSString *key3 = [enKey substringWithRange:NSMakeRange(16, 8)];
    return [PT3Des decrypt:data key1:key1 key2:key2 key3:key3];
    
}


#pragma mark - 加密方法
- (NSData *)encryptData:(NSData *)data withFileName:(NSString *)fileName
{
    // 获取设备号前15位
    NSArray *arr = [fileName componentsSeparatedByString:@"_"];
    NSString *UUID = [arr[2] stringByReplacingOccurrencesOfString:@".log" withString:@""];
    
    int config[] = {33, 22, 88, 44, 77, 66};
    NSMutableString *buffer = [NSMutableString string];
    int start = 0;
    int end = 0;
    
    for (int i = 0; i < 3; i++) {
        start = config[i * 2] % UUID.length;
        end = config[i * 2 + 1] % UUID.length;
        if (start > end) {
            start ^= end;
            end ^= start;
            start ^= end;
        }
        [buffer appendString:[UUID substringWithRange:NSMakeRange(start, end - start)]];
    }
    
    while (buffer.length < 24) {
        [buffer appendString:@"0"];
    }
    NSString *enKey = [UUID stringByAppendingString:buffer];
    NSString *key1 = [enKey substringWithRange:NSMakeRange(0, 8)];
    NSString *key2 = [enKey substringWithRange:NSMakeRange(8, 8)];
    NSString *key3 = [enKey substringWithRange:NSMakeRange(16, 8)];
    return [PT3Des encrypt:data key1:key1 key2:key2 key3:key3];
    
}

@end
