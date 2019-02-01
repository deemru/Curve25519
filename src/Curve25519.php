<?php

namespace deemru;

require 'Curve25519.math.php';
use function deemru\curve25519\sha512;
use function deemru\curve25519\to_chr;
use function deemru\curve25519\to_ord;
use function deemru\curve25519\curve25519_to_ed25519;
use function deemru\curve25519\ed25519_to_curve25519;
use function deemru\curve25519\pack;
use function deemru\curve25519\scalarbase;
use function deemru\curve25519\sign_php;
use function deemru\curve25519\verify_php;

if( !function_exists( 'sodium_crypto_box_publickey_from_secretkey' ) )
{
    function sodium_crypto_box_publickey_from_secretkey( $key )
    {
        $edsk = to_ord( $key, 32 );
        $edsk[0] &= 248;
        $edsk[31] &= 127;
        $edsk[31] |= 64;
        return to_chr( ed25519_to_curve25519( pack( scalarbase( $edsk ) ) ), 32 );
    }
}

if( !function_exists( 'sodium_crypto_sign_verify_detached' ) )
{
    function sodium_crypto_sign_verify_detached( $sig, $msg, $key )
    {
        return verify_php( $sig, $msg, $key );
    }
}

class Curve25519
{
    /**
     * Creates Curve25519 instance
     *
     * @param  bool $caching Caching is enabled by default for the last key used
     */
    public function __construct( $caching = true )
    {
        $this->caching = $caching;
    }

    /**
     * Signs a message with a private key
     *
     * @param  string $msg Message to sign
     * @param  string $key Private key
     * @param  string $rseed Fixed R-value can be used (DANGEROUS)
     *
     * @return string Signature of the message by the private key
     */
    public function sign( $msg, $key, $rseed = null )
    {
        if( strlen( $key ) !== 32 )
            return false;

        if( isset( $rseed ) && !defined( 'IREALLYKNOWWHAT_RSEED_MEANS' ) )
            return false;

        if( $this->caching && isset( $this->skey ) && $this->skey === $key )
        {
            $keypair = $this->skey_val;
        }
        else
        {
            $edsk = to_ord( $key, 32 );
            $edsk[0] &= 248;
            $edsk[31] &= 127;
            $edsk[31] |= 64;

            $edpk = pack( scalarbase( $edsk ) );
            $keypair = array_merge( $edsk, $edpk );
            
            if( $this->caching )
            {
                $this->skey = $key;
                $this->skey_val = $keypair;
            }
        }

        $bit = $keypair[63] & 128;
        $sig = sign_php( $msg, $key, $keypair, $rseed );
        $sig[63] |= $bit;

        return to_chr( $sig, 64 );
    }

    /**
     * Signs a message with a private key by the sodium library (faster but key is prehashed by sha512)
     *
     * @param  string $msg Message to sign
     * @param  string $key Private key which will be hashed by sha512 internally
     *
     * @return string Signature of the message by the private key
     */
    public function sign_sodium( $msg, $key )
    {
        if( !function_exists( 'sodium_crypto_sign_detached' ) )
            return $this->sign( $msg, $this->getSodiumPrivateKeyFromPrivateKey( $key ) );

        if( strlen( $key ) !== 32 )
            return false;

        if( $this->caching && isset( $this->sokey ) && $this->sokey === $key )
        {
            $keypair = $this->sokey_val;
        }
        else
        {
            $edsk = to_ord( sha512( $key ), 32 );
            $edsk[0] &= 248;
            $edsk[31] &= 127;
            $edsk[31] |= 64;

            $edpk = pack( scalarbase( $edsk ) );
            $keypair = $key . to_chr( $edpk, 32 );

            if( $this->caching )
            {
                $this->sokey = $key;
                $this->sokey_val = $keypair;
            }
        }

        $bit = ord( $keypair[63] ) & 128;
        $sig = sodium_crypto_sign_detached( $msg, $keypair );
        $sig[63] = chr( ord( $sig[63] ) | $bit );

        return $sig;
    }

    /**
     * Verifies a signature of a message by a public key
     *
     * @param  string $sig Signature to verify
     * @param  string $msg Message
     * @param  string $key Public key
     *
     * @return bool Returns TRUE if the signature is valid or FALSE on failure
     */
    public function verify( $sig, $msg, $key )
    {
        if( strlen( $key ) !== 32 || strlen( $sig ) !== 64 )
            return false;

        if( $this->caching && isset( $this->pkey ) && $this->pkey === $key )
        {
            $pk = $this->pkey_val;
        }
        else
        {
            $pk = to_chr( curve25519_to_ed25519( to_ord( $key, 32 ) ), 32 );

            if( $this->caching )
            {
                $this->pkey = $key;
                $this->pkey_val = $pk;
            }
        }

        $pk[31] = chr( ord( $pk[31] ) | ( ord( $sig[63] ) & 128 ) );
        $sig[63] = chr( ord( $sig[63] ) & 127 );

        return sodium_crypto_sign_verify_detached( $sig, $msg, $pk );
    }

    /**
     * Gets a public key from a private key
     *
     * @param  string $key Private key
     * @param  bool   $fliplastbit Optionally flip last bit
     *
     * @return string
     */
    public function getPublicKeyFromPrivateKey( $key, $fliplastbit = false )
    {
        $key = sodium_crypto_box_publickey_from_secretkey( $key );
        if( $fliplastbit )
            $key[31] = chr( ord( $key[31] ) ^ 128 );
        return $key;
    }

    /**
     * Gets a "sodium" private key from a private key
     *
     * @param  string $key Private key
     *
     * @return string
     */
    public function getSodiumPrivateKeyFromPrivateKey( $key )
    {
        return substr( sha512( $key ), 0, 32 );
    }

    /**
     * Gets a "sodium" public key from a private key
     *
     * @param  string $key Private key
     * @param  bool   $fliplastbit Optionally flip last bit
     *
     * @return string
     */
    public function getSodiumPublicKeyFromPrivateKey( $key, $fliplastbit = false )
    {
        return self::getPublicKeyFromPrivateKey( self::getSodiumPrivateKeyFromPrivateKey( $key, $fliplastbit ) );
    }
}
