#import <Foundation/Foundation.h>

@interface EncryptionHelper : NSObject

+ (NSData *)aesEncrypt:(NSString *)plainText key:(NSData *)key iv:(NSData *)iv;
//+ (NSString *)aesDecrypt:(NSData *)cipherData key:(NSData *)key iv:(NSData *)iv expectedPlainText:(NSString *)expected;

@end
