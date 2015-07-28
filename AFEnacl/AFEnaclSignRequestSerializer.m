// AFEnaclSignRequestSerializer.m

#include <sodium.h>

#import "AFEnaclSignRequestSerializer.h"


@interface AFEnaclSignRequestSerializer ()
@property (readwrite, nonatomic, strong) id <AFURLRequestSerialization> serializer;
@property (readwrite, nonatomic, strong) NSData secret_key;
@end

@implementation AFEnaclSignRequestSerializer

+ (instancetype)serializerWithSerializer:(id<AFURLRequestSerialization>)serializer
                               secretKey:(NSData) sk
{
    AFEnaclSignRequestSerializer *enaclSignSerializer = [self serializer];
    enaclSignSerializer.serializer = serializer;
    enaclSignSerializer.secret_key = sk;

    return enaclSignSerializer;
}

#pragma mark - AFURLRequestSerialization

- (NSURLRequest *)requestBySerializingRequest:(NSURLRequest *)request
                               withParameters:(id)parameters
                                        error:(NSError * __autoreleasing *)error
{

    NSError *serializationError = nil;
    NSMutableURLRequest *mutableRequest = [[self.serializer requestBySerializingRequest:request withParameters:parameters error:&serializationError] mutableCopy];

    [self.HTTPRequestHeaders enumerateKeysAndObjectsUsingBlock:^(id field, id value, BOOL * __unused stop) {
        if (![request valueForHTTPHeaderField:field]) {
            [mutableRequest setValue:value forHTTPHeaderField:field];
        }
    }];

    unsigned long long message_len = [mutableRequest.HTTPBody length];
    unsigned long long message_signed_len;
    unsigned char message_sig[crypto_sign_BYTES + message_len];
    unsigned char message[message_len];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];

    if (!serializationError && mutableRequest.HTTPBody) {
        // Extract the raw bytes from NSData
        [mutableRequest.HTTPBody getBytes:&message length:message_len];
        [self.secret_key getBytes:&sk length:[self.secret_key length]];

        crypto_sign(message_sig, &message_signed_len, message, message_len, sk);

        [mutableRequest setValue:message_sig forHTTPHeaderField:@"X-Content-Signature"];
        [mutableRequest setHTTPBody:mutableRequest.HTTPBody];
    } else {
        if (error) {
            *error = serializationError;
        }
    }

    return mutableRequest;
}

#pragma mark - NSCoder

- (id)initWithCoder:(NSCoder *)decoder {
    self = [super init];
    if (!self) {
        return nil;
    }

    self.serializer = [decoder decodeObjectForKey:NSStringFromSelector(@selector(serializer))];

    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [super encodeWithCoder:coder];

    [coder encodeObject:self.serializer forKey:NSStringFromSelector(@selector(serializer))];
}

#pragma mark - NSCopying

- (id)copyWithZone:(NSZone *)zone {
    AFEnaclSignRequestSerializer *serializer = [[[self class] allocWithZone:zone] init];
    serializer.serializer = self.serializer;

    return serializer;
}

@end
