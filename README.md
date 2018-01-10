# TOTP Authenticator
A Java implementation of [TOTP(time-base one-time password)](https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm) and the  algorithm is described in [rfc6238](https://tools.ietf.org/html/rfc6238).

## Features
* Generate TOTP with a secret key
* Validate TOTP according to the secret key and the totp from prover

## Quick start
### Add Maven dependency
```xml
<dependency>
   <groupId>com.github.cheergoivan</groupId>
   <artifactId>totp-authenticator</artifactId>
   <version>1.0</version>
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

## License
This project is licensed under the [Apache 2 License](http://www.apache.org/licenses/LICENSE-2.0).

