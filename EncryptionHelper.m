#import "EncryptionHelper.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation EncryptionHelper

+ (NSData *)aesEncrypt:(NSString *)plainText key:(NSData *)key iv:(NSData *)iv {
    NSData *data = [plainText dataUsingEncoding:NSUTF8StringEncoding];


    
    
    
    
//    NSLog(@"[EncryptionHelper] 🔓 原始明文文字: %@", plainText);
//    NSLog(@"[EncryptionHelper] 🔓 原始key: %@", key);
//    NSLog(@"[EncryptionHelper] 🔓 原始iv: %@", iv);
//    NSLog(@"[EncryptionHelper] 📏 明文長度: %lu", (unsigned long)data.length);
//    NSLog(@"[EncryptionHelper] 🔑 Key 長度: %lu", (unsigned long)key.length);
//    NSLog(@"[EncryptionHelper] 🧊 IV 長度 : %lu", (unsigned long)iv.length);

    // 檢查 key/iv 長度是否正確 (AES-128)
    if (key.length != kCCKeySizeAES128 || iv.length != kCCBlockSizeAES128) {
        NSLog(@"❌ 錯誤：Key 或 IV 長度不符");
        return nil;
    }

    size_t outLength;
    NSMutableData *cipherData = [NSMutableData dataWithLength:data.length + kCCBlockSizeAES128];

    CCCryptorStatus result = CCCrypt(kCCEncrypt,
                                     kCCAlgorithmAES,
                                     kCCOptionPKCS7Padding,
                                     key.bytes,
                                     key.length,
                                     iv.bytes,
                                     data.bytes,
                                     data.length,
                                     cipherData.mutableBytes,
                                     cipherData.length,
                                     &outLength);

    if (result == kCCSuccess) {
        cipherData.length = outLength;

        // 顯示加密結果（Hex）
        NSMutableString *hexString = [NSMutableString stringWithCapacity:outLength * 2];
        const unsigned char *bytes = cipherData.bytes;
        for (int i = 0; i < outLength; i++) {
            [hexString appendFormat:@"%02x", bytes[i]];
        }



        // sSave the file so that it can be accessed by the Python code.
        NSString *filePath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/encrypted.txt"];
//        [hexString writeToFile:filePath atomically:YES encoding:NSUTF8StringEncoding error:nil];
//        要存成cipherData時用以下，在python搭配也要用with open(...,'wb')
        [cipherData writeToFile:filePath atomically:YES];
        
//        NSLog(@"[EncryptionHelper] 🔐 加密結果 (Hex): %@", hexString);
//        NSLog(@"[EncryptionHelper] 🔐 加密內容: %@", cipherData);
//        NSLog(@"[EncryptionHelper] 🔐 CipherData length: %lu", cipherData.length);

        
        
        return cipherData;
    } else {
        NSLog(@"❌ 加密失敗，狀態碼: %d", result);
        return nil;
    }
}


//+ (NSString *)aesDecrypt:(NSData *)cipherData key:(NSData *)key iv:(NSData *)iv expectedPlainText:(NSString *)expected {
//    NSLog(@"[EncryptionHelper] 📦 解密資料長度: %lu", (unsigned long)cipherData.length);
//    NSLog(@"[EncryptionHelper] 🧪 預期明文: %@", expected);
//
//    if (key.length != kCCKeySizeAES128 || iv.length != kCCBlockSizeAES128) {
//        NSLog(@"❌ 錯誤：Key 或 IV 長度不符");
//        return nil;
//    }
//
//    size_t outLength;
//    NSMutableData *plainData = [NSMutableData dataWithLength:cipherData.length + kCCBlockSizeAES128];
//
//    CCCryptorStatus result = CCCrypt(kCCDecrypt,
//                                     kCCAlgorithmAES,
//                                     kCCOptionPKCS7Padding,
//                                     key.bytes,
//                                     key.length,
//                                     iv.bytes,
//                                     cipherData.bytes,
//                                     cipherData.length,
//                                     plainData.mutableBytes,
//                                     plainData.length,
//                                     &outLength);
//
//    if (result == kCCSuccess) {
//        plainData.length = outLength;
//
//        NSString *plainText = [[NSString alloc] initWithData:plainData encoding:NSUTF8StringEncoding];
//        NSLog(@"[EncryptionHelper] ✅ 解密成功文字: %@", plainText);
//
//        // 比對與 Python 傳入的預期值是否一致
//        if ([plainText isEqualToString:expected]) {
//            NSLog(@"✅ 解密結果與預期明文一致");
//        } else {
//            NSLog(@"❌ 解密結果與預期明文不符");
//        }
//
//        return plainText;
//    } else {
//        NSLog(@"❌ 解密失敗，狀態碼: %d", result);
//        return nil;
//    }
//}



@end
