# Curve25519

[![packagist](https://img.shields.io/packagist/v/deemru/curve25519.svg)](https://packagist.org/packages/deemru/curve25519) [![php-v](https://img.shields.io/packagist/php-v/deemru/curve25519.svg)](https://packagist.org/packages/deemru/curve25519)  [![travis](https://img.shields.io/travis/deemru/Curve25519.svg?label=travis)](https://travis-ci.org/deemru/Curve25519) [![codacy](https://img.shields.io/codacy/grade/49e6e148e477494da94320825c715dfd.svg?label=codacy)](https://app.codacy.com/gh/deemru/Curve25519/files) [![license](https://img.shields.io/packagist/l/deemru/curve25519.svg)](https://packagist.org/packages/deemru/curve25519)

[Curve25519](https://github.com/deemru/Curve25519) implements the missing functionality of sign/verify on [elliptic curve 25519](https://en.wikipedia.org/wiki/Curve25519).

- Cryptographically compatible sign/verify
- Built in cache for last key calculations
- Sodium variant of the sign function (~2000x faster)

## Usage

```php
$curve25519 = new Curve25519();
$msg = 'Hello, world!';

$privateKey = random_bytes( 32 );
$sig = $curve25519->sign( $msg, $privateKey );

$publicKey = $curve25519->getPublicKeyFromPrivateKey( $privateKey );
$verify = $curve25519->verify( $sig, $msg, $publicKey );

if( !$verify )
    exit( 1 );
```

## Requirements

- [PHP](http://php.net) >= 5.6

## Recommended

- [PHP](http://php.net) >= 7.2
- [Sodium](http://php.net/manual/en/book.sodium.php)

## Installation

Require through Composer:

```json
{
    "require": {
        "deemru/curve25519": "1.0.*"
    }
}
```

## Notice

- `sign_sodium` hashes private key internally by SHA-512
- Beware of `rseed` functionality (for experts only)
- Consider to use [ED25519_NO_SHA512SK sodium build](https://gist.github.com/deemru/145c3eb323bb3fb0f1cc4a72f5567640)
