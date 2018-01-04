# TOTP Authenticator
A Java implemetation of [TOTP(time-base one-time password)](https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm) and the  algorithm is described in [rfc6238](https://tools.ietf.org/html/rfc6238).

## Features
* Generate TOTP with a secret key
* Validate TOTP  according to the secret key and the totp from prover

## Quick start
### Add Maven dependency
```xml
<dependency>
   <groupId>com.paypal.springboot</groupId>
   <artifactId>resteasy-spring-boot-starter</artifactId>
   <version>2.3.4-RELEASE</version>
</dependency>
```
### Usage
```java
TOTPAuthenticator auth = TOTPAuthenticator.builder().build();
String secret = "jsjbdfislfd";
String totp = auth.generateTOTP(secret);
System.out.println(totp);
System.out.println(auth.validateTOTP(secret, totp));
```

