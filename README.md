# kivy-ios_encrypt

### Since both PyCrypto and PyCryptodome cause issues in kivy-ios, I switched to another solution instead.

### do not build/pip install pycrypto/pycryptodome kivy-ios, it will cause fail to upload app to apple connect

1. create encrypthelper.h:
```
#import <Foundation/Foundation.h>

@interface EncryptionHelper : NSObject

+ (NSData *)aesEncrypt:(NSString *)plainText key:(NSData *)key iv:(NSData *)iv;
//+ (NSString *)aesDecrypt:(NSData *)cipherData key:(NSData *)key iv:(NSData *)iv expectedPlainText:(NSString *)expected;

@end
```
2. create encrypthelper.m:
```
#import "EncryptionHelper.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation EncryptionHelper

+ (NSData *)aesEncrypt:(NSString *)plainText key:(NSData *)key iv:(NSData *)iv {
    NSData *data = [plainText dataUsingEncoding:NSUTF8StringEncoding];

    // for check 
    NSLog(@"[EncryptionHelper] 🔓 origin text: %@", plainText);
    NSLog(@"[EncryptionHelper] 🔓 orgin key: %@", key);
    NSLog(@"[EncryptionHelper] 🔓 origin iv: %@", iv);
    NSLog(@"[EncryptionHelper] 📏 text length: %lu", (unsigned long)data.length);
    NSLog(@"[EncryptionHelper] 🔑 Key length: %lu", (unsigned long)key.length);
    NSLog(@"[EncryptionHelper] 🧊 IV length : %lu", (unsigned long)iv.length);

    // check if length key/iv length correct (AES-128)
    if (key.length != kCCKeySizeAES128 || iv.length != kCCBlockSizeAES128) {
        NSLog(@"❌ failed ：incoorect length Key or IV ");
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

        // show result（Hex）
        NSMutableString *hexString = [NSMutableString stringWithCapacity:outLength * 2];
        const unsigned char *bytes = cipherData.bytes;
        for (int i = 0; i < outLength; i++) {
            [hexString appendFormat:@"%02x", bytes[i]];
        }

        NSString *filePath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/encrypted.txt"];
        [cipherData writeToFile:filePath atomically:YES];
        NSLog(@"[EncryptionHelper] 🔐 encrypt result (Hex): %@", hexString);
        NSLog(@"[EncryptionHelper] 🔐 encrypt result : %@", cipherData);
        NSLog(@"[EncryptionHelper] 🔐 CipherData length: %lu", cipherData.length);

        
        
        return cipherData;
    } else {
        NSLog(@"❌ encrypt failed code: %d", result);
        return nil;
    }
}

@end
```
3. add python code :

send encryption data
```
    def encrypt_with_objc(self, text: str, key: bytes, iv: bytes) -> bytes:
        import ctypes

        load_framework(INCLUDE.Foundation)
        NSData = autoclass('NSData')
        EncryptionHelper = autoclass('EncryptionHelper')

        # create memory buffer and cast to void*
        key_buffer = ctypes.create_string_buffer(key)
        iv_buffer = ctypes.create_string_buffer(iv)

        key_ptr = ctypes.cast(key_buffer, ctypes.c_void_p)
        iv_ptr = ctypes.cast(iv_buffer, ctypes.c_void_p)

        key_ns = NSData.dataWithBytes_length_(key_ptr.value, len(key))
        iv_ns = NSData.dataWithBytes_length_(iv_ptr.value, len(iv))

        result = EncryptionHelper.aesEncrypt_key_iv_(text, key_ns, iv_ns)
```

```
from pyobjus import autoclass
from pyobjus.dylib_manager import load_framework, INCLUDE
from ctypes import create_string_buffer
import base64

text = "Hello from Kivy"
key = b"thisisakey123456"      # 16 bytes
iv = b"ivmustbe16bytes!"       # 16 bytes
encrypted = self.encrypt_with_objc(text, key, iv)
```

read endrypted file:
```
def read_encrypt_file():
    file_path = os.path.expanduser("~/Documents/encrypted.txt")
    if os.path.exists(file_path):
        with open(file_path, "rb") as f:
            return f.read().strip()
        return None
    encrypted = read_encrypt_file()

    print(f'encrypted data in python:{encrypted}')
```

