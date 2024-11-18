//
// MQTTSSLSecurityPolicy.m
// MQTTClient.framework
//
// Created by @bobwenx on 15/6/1.
//
// based on
//
// Copyright (c) 2011–2015 AFNetwork (http://alamofire.org/)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "MQTTSSLSecurityPolicy.h"
#import <AssertMacros.h>
#import <Security/Security.h>
#import <Foundation/Foundation.h>
#import "MQTTLog.h"

static BOOL SSLSecKeyIsEqualToKey(SecKeyRef key1, SecKeyRef key2) {
    return [(__bridge id) key1 isEqual:(__bridge id) key2];
}

static id SSLPublicKeyForCertificate(NSData *certificate) {
    id allowedPublicKey = nil;
    SecCertificateRef allowedCertificate;
    SecPolicyRef policy = nil;
    SecTrustRef allowedTrust = nil;
    
    allowedCertificate = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certificate);
    __Require_Quiet(allowedCertificate != NULL, _out);
    
    policy = SecPolicyCreateBasicX509();
    
    if (@available(iOS 13.0, *)) {
        CFArrayRef certs = CFArrayCreate(NULL, (const void **)&allowedCertificate, 1, NULL);
        __Require_noErr_Quiet(SecTrustCreateWithCertificates(certs, policy, &allowedTrust), _out);
        
        CFErrorRef error = NULL;
        BOOL result = SecTrustEvaluateWithError(allowedTrust, &error);
        if (!result) {
            if (error) {
                DDLogError(@"Trust evaluation failed: %@", error);
                CFRelease(error);
            }
            goto _out;
        }
        
        if (@available(iOS 14.0, *)) {
            allowedPublicKey = (__bridge_transfer id)SecTrustCopyKey(allowedTrust);
        } else {
            allowedPublicKey = (__bridge_transfer id)SecTrustCopyPublicKey(allowedTrust);
        }
        
        CFRelease(certs);
    } else {
        CFArrayRef certs = CFArrayCreate(NULL, (const void **)&allowedCertificate, 1, NULL);
        __Require_noErr_Quiet(SecTrustCreateWithCertificates(certs, policy, &allowedTrust), _out);
        
        SecTrustResultType result;
        __Require_noErr_Quiet(SecTrustEvaluate(allowedTrust, &result), _out);
        allowedPublicKey = (__bridge_transfer id)SecTrustCopyPublicKey(allowedTrust);
        
        CFRelease(certs);
    }
    
_out:
    if (allowedTrust) CFRelease(allowedTrust);
    if (policy) CFRelease(policy);
    if (allowedCertificate) CFRelease(allowedCertificate);
    
    return allowedPublicKey;
}

static BOOL SSLServerTrustIsValid(SecTrustRef serverTrust) {
    if (@available(iOS 13.0, *)) {
        CFErrorRef error = NULL;
        BOOL result = SecTrustEvaluateWithError(serverTrust, &error);
        if (error) {
            DDLogError(@"Trust evaluation failed: %@", error);
            CFRelease(error);
        }
        return result;
    } else {
        SecTrustResultType result;
        OSStatus status = SecTrustEvaluate(serverTrust, &result);
        
        if (status != errSecSuccess) {
            return NO;
        }
        
        return (result == kSecTrustResultUnspecified || 
                result == kSecTrustResultProceed);
    }
}

static NSArray * SSLCertificateTrustChainForServerTrust(SecTrustRef serverTrust) {
    NSMutableArray *trustChain = [NSMutableArray array];
    
    if (@available(iOS 15.0, *)) {
        CFArrayRef certificates = SecTrustCopyCertificateChain(serverTrust);
        if (certificates) {
            CFIndex count = CFArrayGetCount(certificates);
            for (CFIndex i = 0; i < count; i++) {
                SecCertificateRef certificate = (SecCertificateRef)CFArrayGetValueAtIndex(certificates, i);
                [trustChain addObject:(__bridge_transfer NSData *)SecCertificateCopyData(certificate)];
            }
            CFRelease(certificates);
        }
    } else {
        CFIndex certificateCount = SecTrustGetCertificateCount(serverTrust);
        for (CFIndex i = 0; i < certificateCount; i++) {
            SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
            [trustChain addObject:(__bridge_transfer NSData *)SecCertificateCopyData(certificate)];
        }
    }
    
    return [NSArray arrayWithArray:trustChain];
}

static NSArray * SSLPublicKeyTrustChainForServerTrust(SecTrustRef serverTrust) {
    NSMutableArray *trustChain = [NSMutableArray array];
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    
    if (@available(iOS 15.0, *)) {
        CFArrayRef certificates = SecTrustCopyCertificateChain(serverTrust);
        if (certificates) {
            CFIndex count = CFArrayGetCount(certificates);
            for (CFIndex i = 0; i < count; i++) {
                SecCertificateRef certificate = (SecCertificateRef)CFArrayGetValueAtIndex(certificates, i);
                SecCertificateRef certs[] = {certificate};
                CFArrayRef certsArray = CFArrayCreate(NULL, (const void **)certs, 1, NULL);
                
                SecTrustRef trust;
                if (SecTrustCreateWithCertificates(certsArray, policy, &trust) == errSecSuccess) {
                    if (@available(iOS 14.0, *)) {
                        [trustChain addObject:(__bridge_transfer id)SecTrustCopyKey(trust)];
                    } else {
                        [trustChain addObject:(__bridge_transfer id)SecTrustCopyPublicKey(trust)];
                    }
                    CFRelease(trust);
                }
                CFRelease(certsArray);
            }
            CFRelease(certificates);
        }
    } else {
        CFIndex certificateCount = SecTrustGetCertificateCount(serverTrust);
        for (CFIndex i = 0; i < certificateCount; i++) {
            SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
            SecCertificateRef certs[] = {certificate};
            CFArrayRef certsArray = CFArrayCreate(NULL, (const void **)certs, 1, NULL);
            
            SecTrustRef trust;
            if (SecTrustCreateWithCertificates(certsArray, policy, &trust) == errSecSuccess) {
                if (@available(iOS 14.0, *)) {
                    [trustChain addObject:(__bridge_transfer id)SecTrustCopyKey(trust)];
                } else {
                    [trustChain addObject:(__bridge_transfer id)SecTrustCopyPublicKey(trust)];
                }
                CFRelease(trust);
            }
            CFRelease(certsArray);
        }
    }
    
    CFRelease(policy);
    return [NSArray arrayWithArray:trustChain];
}

@interface MQTTSSLSecurityPolicy()
@property (readwrite, nonatomic, assign) MQTTSSLPinningMode SSLPinningMode;
@property (readwrite, nonatomic, strong) NSArray *pinnedPublicKeys;
@end

@implementation MQTTSSLSecurityPolicy

// [Rest of your existing implementation remains unchanged]

@end
