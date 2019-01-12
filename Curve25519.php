<?php

namespace deemru;

require 'Curve25519.math.php';
use function deemru\curve25519\sha512;
use function deemru\curve25519\to_chr;
use function deemru\curve25519\to_ord;
use function deemru\curve25519\curve25519_to_ed25519;
use function deemru\curve25519\pack;
use function deemru\curve25519\scalarbase;
use function deemru\curve25519\sign_php;

class Curve25519
{
    private $caching;

    public function __construct( $caching = true )
    {
        $this->caching = $caching;
    }

    private function cache( $key, $edpk = null )
    {
        static $cache = [];

        if( isset( $edpk ) )
        {
            if( count( $cache ) >= 1024 )
                $cache = [];

            $cache[$key] = $edpk;
            return $edpk;
        }

        if( isset( $cache[$key] ) )
            return $cache[$key];

        return null;
    }

    public function sign( $msg, $key, $rseed = null )
    {
        if( strlen( $key ) !== 32 )
            return false;

        if( isset( $rseed ) && !defined( 'IREALLYKNOWWHAT_RSEED_MEANS' ) )
            return false;

        if( !$this->caching || null === ( $keypair = $this->cache( 's' . $key ) ) )
        {
            $edsk = to_ord( $key, 32 );
            $edsk[0] &= 248;
            $edsk[31] &= 127;
            $edsk[31] |= 64;

            $edpk = pack( scalarbase( $edsk ) );
            $keypair = $this->cache( 's' . $key, array_merge( $edsk, $edpk ) );
        }

        $bit = $keypair[63] & 128;
        $sig = sign_php( $msg, $key, $keypair, $rseed );
        $sig[63] |= $bit;

        return to_chr( $sig, 64 );
    }

    public function sign_sodium( $msg, $key )
    {
        if( strlen( $key ) !== 32 )
            return false;

        if( !$this->caching || null === ( $keypair = $this->cache( 'k' . $key ) ) )
        {
            $edsk = to_ord( sha512( $key ), 32 );
            $edsk[0] &= 248;
            $edsk[31] &= 127;
            $edsk[31] |= 64;

            $edpk = pack( scalarbase( $edsk ) );
            $keypair = $this->cache( 'k' . $key, $key . to_chr( $edpk, 32 ) );
        }

        $bit = ord( $keypair[63] ) & 128;
        $sig = sodium_crypto_sign_detached( $msg, $keypair );
        $sig[63] = chr( ord( $sig[63] ) | $bit );

        return $sig;
    }

    public function verify( $sig, $msg, $key )
    {
        if( strlen( $key ) !== 32 || strlen( $sig ) !== 64 )
            return false;

        $pk = $this->cache( 'p' . $key );
        if( !isset( $pk ) )
            $pk = $this->cache( 'p' . $key, to_chr( curve25519_to_ed25519( to_ord( $key, 32 ) ), 32 ) );

        $pk[31] = chr( ord( $pk[31] ) | ( ord( $sig[63] ) & 128 ) );
        $sig[63] = chr( ord( $sig[63] ) & 127 );

        return sodium_crypto_sign_verify_detached( $sig, $msg, $pk );
    }
}