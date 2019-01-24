<?php

namespace deemru\curve25519;

// Based on: http://tweetnacl.cr.yp.to/20140427/tweetnacl.c

function car25519( &$o )
{
    $c = 1;

    for( $i = 0; $i < 16; $i++ )
    {
        $v = $o[$i] + $c + 65535;
        $c = floor( $v / 65536 );
        $o[$i] = $v - $c * 65536;
    }

    $o[0] += $c - 1 + 37 * ( $c - 1 );
}

function sel25519( &$p, &$q, $b )
{
    $c = ~( $b - 1 );

    for( $i = 0; $i < 16; $i++ )
    {
        $t = $c & ( $p[$i] ^ $q[$i] );
        $p[$i] ^= $t;
        $q[$i] ^= $t;
    }
}

function pack25519( $n )
{
    $m = [];
    $t = [];

    for( $i = 0; $i < 16; $i++ )
        $t[$i] = $n[$i];

    car25519( $t );
    car25519( $t );
    car25519( $t );

    for( $j = 0; $j < 2; $j++ )
    {
        $m[0] = $t[0] - 0xFFED;

        for( $i = 1; $i < 15; $i++ )
        {
            $m[$i] = $t[$i] - 0xFFFF - (( $m[$i - 1] >> 16 ) & 1 );
            $m[$i - 1] &= 0xFFFF;
        }

        $m[15] = $t[15] - 0x7FFF - (( $m[14] >> 16 ) & 1 );
        $b = ( $m[15] >> 16 ) & 1;
        $m[14] &= 0xFFFF;
        sel25519( $t, $m, 1 - $b );
    }

    $o = [];
    for( $i = 0; $i < 16; $i++ )
    {
        $o[] = $t[$i] & 0xFF;
        $o[] = $t[$i] >> 8;
    }

    return $o;
}

function par25519( $a )
{
    return pack25519( $a )[0] & 1;
}

function unpack25519( $n )
{
    $o = [];
    for( $i = 0; $i < 16; $i++ )
        $o[$i] = $n[2 * $i] + ( $n[2 * $i + 1] << 8 );

    $o[15] &= 0x7FFF;
    return $o;
}

function A( &$o, $a, $b )
{
    for( $i = 0; $i < 16; $i++ )
        $o[$i] = $a[$i] + $b[$i];
}

function Z( &$o, $a, $b )
{
    for( $i = 0; $i < 16; $i++ )
        $o[$i] = $a[$i] - $b[$i];
}

function M( &$o, $a, $b )
{
    $t = array_fill( 0, 31, 0 );

    for( $i = 0; $i < 16; $i++ )
        for( $j = 0; $j < 16; $j++ )
            $t[$i + $j] += $a[$i] * $b[$j];

    for( $i = 0; $i < 15; $i++ )
        $t[$i] += 38 * $t[$i + 16];

    for( $i = 0; $i < 16; $i++ )
        $o[$i] = $t[$i];

    car25519( $o );
    car25519( $o );
}

function S( &$o, $a )
{
    M( $o, $a, $a );
}

function inv25519( &$o, $i )
{
    $c = [];
    for( $a = 0; $a < 16; $a++ )
        $c[$a] = $i[$a];

    for( $a = 253; $a >= 0; $a-- )
    {
        S( $c, $c );
        if( $a !== 2 && $a !== 4 )
            M( $c, $c, $i );
    }

    for( $a = 0; $a < 16; $a++ )
        $o[$a] = $c[$a];
}

function add( &$p, $q )
{
    $a = [];
    $b = [];
    $c = [];
    $d = [];
    $e = [];
    $f = [];
    $g = [];
    $h = [];
    $t = [];
    static $D2 = [ 61785, 9906, 39828, 60374, 45398, 33411, 5274, 224, 53552, 61171, 33010, 6542, 64743, 22239, 55772, 9222 ];

    Z( $a, $p[1], $p[0] );
    Z( $t, $q[1], $q[0] );
    M( $a, $a, $t );
    A( $b, $p[0], $p[1] );
    A( $t, $q[0], $q[1] );
    M( $b, $b, $t );
    M( $c, $p[3], $q[3] );
    M( $c, $c, $D2 );
    M( $d, $p[2], $q[2] );
    A( $d, $d, $d );
    Z( $e, $b, $a );
    Z( $f, $d, $c );
    A( $g, $d, $c );
    A( $h, $b, $a );

    M( $p[0], $e, $f );
    M( $p[1], $h, $g );
    M( $p[2], $g, $f );
    M( $p[3], $e, $h );
}

function cswap( &$p, &$q, $b )
{
    for( $i = 0; $i < 4; $i++ )
        sel25519( $p[$i], $q[$i], $b );
}

function pack( $p )
{
    $tx = [];
    $ty = [];
    $zi = [];

    inv25519( $zi, $p[2] );
    M( $tx, $p[0], $zi );
    M( $ty, $p[1], $zi );
    $r = pack25519( $ty );
    $r[31] ^= par25519( $tx ) << 7;
    return $r;
}

function scalarmult( $q, $s )
{
    $p = [ [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ],
           [ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ],
           [ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ],
           [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ] ];

    for( $i = 255; $i >= 0; $i-- )
    {
        $b = ( $s[( $i / 8 ) | 0] >> ( $i & 7 )) & 1;
        cswap( $p, $q, $b );
        add( $q, $p );
        add( $p, $p );
        cswap( $p, $q, $b );
    }

    return $p;
}

function scalarbase( $s )
{
    static $q = [ [ 54554, 36645, 11616, 51542, 42930, 38181, 51040, 26924, 56412, 64982, 57905, 49316, 21502, 52590, 14035, 8553 ],
                  [ 26200, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214 ],
                  [ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ],
                  [ 56720, 42423, 35507, 28126, 21237, 30545, 40832, 8432, 58237, 25771, 20110, 26346, 30309, 55179, 24335, 59271 ] ];

    return scalarmult( $q, $s );
}

function modL( $x )
{
    static $L = [ 237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ];

    for( $i = 63; $i >= 32; $i-- )
    {
        $carry = 0;

        for( $j = $i - 32, $k = $i - 12; $j < $k; $j++ )
        {
            $x[$j] += $carry - 16 * $x[$i] * $L[$j - ( $i - 32 )];
            $carry = ( $x[$j] + 128 ) >> 8;
            $x[$j] -= $carry * 256;
        }

        $x[$j] += $carry;
        $x[$i] = 0;
    }

    $carry = 0;

    for( $j = 0; $j < 32; $j++ )
    {
        $x[$j] += $carry - ( $x[31] >> 4 ) * $L[$j];
        $carry = $x[$j] >> 8;
        $x[$j] &= 255;
    }

    for( $j = 0; $j < 32; $j++ )
        $x[$j] -= $carry * $L[$j];

    $r = [];
    for( $i = 0; $i < 32; $i++ )
    {
        $x[$i+1] += $x[$i] >> 8;
        $r[] = $x[$i] & 255;
    }

    return $r;
}

function sha512( $data )
{
    return hash( 'sha512', $data, true );
}

function to_ord( $a, $n )
{
    $ord = [];
    for( $i = 0; $i < $n; $i++ )
        $ord[] = ord( $a[$i] );

    return $ord;
}

function to_chr( $a, $n )
{
    $chr = '';
    for( $i = 0; $i < $n; $i++ )
        $chr .= chr( $a[$i] );

    return $chr;
}

function sign_php( $msg, $key, $sk, $rseed )
{
    if( isset( $rseed ) )
        $rseed = str_pad( chr( 254 ), 32, chr( 255 ) ) . $key . sha512( $rseed );
    else
        $rseed = str_pad( chr( 254 ), 32, chr( 255 ) ) . $key . $msg . random_bytes( 64 );

    $r = modL( to_ord( sha512( $rseed ), 64 ) );
    $R = pack( scalarbase( $r ) );

    $S = array_fill( 0, 32, 0 );
    if( isset( $rseed ) && !isset( $msg ) )
        return array_merge( $R, $S );

    $rseed = to_chr( $R, 32 );
    for( $i = 0; $i < 32; $i++ )
        $rseed .= chr( $sk[32 + $i] );
    $h = modL( to_ord( sha512( $rseed . $msg ), 64 ) );

    $x = array_merge( $r, array_fill( 0, 32, 0 ) );
    for( $i = 0; $i < 32; $i++ )
        for( $j = 0; $j < 32; $j++ )
            $x[$i + $j] += $h[$i] * $sk[$j];
    $S = modL( $x );

    return array_merge( $R, $S );
}

function gf1(){ return [ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]; }

function curve25519_to_ed25519( $pk )
{
    $a = [];
    $b = [];
    $x = unpack25519( $pk );
    A( $a, $x, gf1() );
    Z( $b, $x, gf1() );
    inv25519( $a, $a );
    M( $a, $a, $b );
    return pack25519( $a );
}

function ed25519_to_curve25519( $pk )
{
    $a = [];
    $b = [];
    $x = unpack25519( $pk );
    A( $a, gf1(), $x );
    Z( $b, gf1(), $x );
    inv25519( $b, $b );
    M( $a, $a, $b );
    return pack25519( $a );
}
