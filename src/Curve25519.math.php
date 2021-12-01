<?php

namespace deemru\curve25519;

// Based on: http://tweetnacl.cr.yp.to/20140427/tweetnacl.c

function car25519( &$o )
{
    $c = 1;

    for( $i = 0; $i < 16; $i++ )
    {
        $v = $o[$i] + $c + 65535;
        $c = $v >> 16;
        $o[$i] = $v & 65535;
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
        $b = ( $s[$i >> 3] >> ( $i & 7 )) & 1;
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

function rnd( $size )
{
    static $rndfn;

    if( !isset( $rndfn ) )
    {
        if( function_exists( 'random_bytes' ) )
            $rndfn = 2;
        else if( function_exists( 'mcrypt_create_iv' ) )
            $rndfn = 1;
        else
            $rndfn = 0;
    }
    
    if( $rndfn === 2 )
        return random_bytes( $size );
    if( $rndfn === 1 )
        return mcrypt_create_iv( $size );

    $rnd = '';
    while( $size-- )
        $rnd .= chr( mt_rand() );
    return $rnd;
}

function sign_php( $msg, $key, $sk, $rseed )
{
    if( isset( $rseed ) )
        $rseed = str_pad( chr( 254 ), 32, chr( 255 ) ) . $key . sha512( $rseed );
    else
        $rseed = str_pad( chr( 254 ), 32, chr( 255 ) ) . $key . $msg . rnd( 64 );

    $r = modL( to_ord( sha512( $rseed ), 64 ) );
    $R = pack( scalarbase( $r ) );

    if( !isset( $msg ) )
        return $R;

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

function pow2523( &$o, $i )
{
    $c = [];
    for( $a = 0; $a < 16; $a++ )
        $c[$a] = $i[$a];

    for( $a = 250; $a >= 0; $a-- )
    {
        S( $c, $c );
        if( $a !== 1 )
            M( $c, $c, $i );
    }

    for( $a = 0; $a < 16; $a++ )
        $o[$a] = $c[$a];
}

function crypto_verify_32( $x, $y )
{
    $d = 0;
    for( $i = 0; $i < 32; $i++ )
        $d |= $x[$i] ^ $y[$i];
    return ( 1 & (( $d - 1 ) >> 8 )) - 1;
}

function neq25519( $a, $b )
{
    $c = pack25519( $a );
    $d = pack25519( $b );
    return crypto_verify_32( $c, $d );
}

function unpackneg( &$r, $p )
{
    $r[1] = unpack25519( $p );
    $r[2] = gf1();

    $num = [];
    $den = [];
    $den2 = [];
    $den4 = [];
    $den6 = [];
    $t = [];
    $chk = [];
    static $D = [ 30883, 4953, 19914, 30187, 55467, 16705, 2637, 112, 59544, 30585, 16505, 36039, 65139, 11119, 27886, 20995 ];
    static $I = [ 41136, 18958, 6951, 50414, 58488, 44335, 6150, 12099, 55207, 15867, 153, 11085, 57099, 20417, 9344, 11139 ];

    S( $num, $r[1] );
    M( $den, $num, $D );
    Z( $num, $num, $r[2] );
    A( $den, $r[2], $den );

    S( $den2, $den );
    S( $den4, $den2 );
    M( $den6, $den4, $den2 );
    M( $t, $den6, $num );
    M( $t, $t, $den );

    pow2523( $t, $t );
    M( $t, $t, $num );
    M( $t, $t, $den );
    M( $t, $t, $den );
    M( $r[0], $t, $den );

    S( $chk, $r[0] );
    M( $chk, $chk, $den );
    if( neq25519( $chk, $num ) )
        M( $r[0], $r[0], $I );

    S( $chk, $r[0] );
    M( $chk, $chk, $den );
    if( neq25519( $chk, $num ) )
        return -1;

    if( par25519( $r[0] ) === ( $p[31] >> 7 ) )
        Z( $r[0], [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ], $r[0] );

    M( $r[3], $r[0], $r[1] );
    return 0;
}

function verify_php( $sig, $msg, $key )
{
    $q = [];
    if( unpackneg( $q, to_ord( $key, 32 ) ) )
        return false;

    $m = substr( $sig, 0, 32 ) . $key . $msg;
    $h = modL( to_ord( sha512( $m ), 64 ) );

    $p = scalarmult( $q, $h );
    $q = scalarbase( to_ord( substr( $sig, 32 ), 32 ) );

    add( $p, $q );
    $t = pack( $p );

    if( crypto_verify_32( to_ord( $sig, 32 ), $t ) )
        return false;

    return true;
}

function keypair( $keyseed, $sodium, $CURVE25519_SODIUM_SUPPORT )
{
    if( $CURVE25519_SODIUM_SUPPORT )
    {
        if( $sodium )
            return substr( sodium_crypto_sign_seed_keypair( substr( sha512( $keyseed ), 0, 32 ) ), 0, 64 );
        else
            return substr( sodium_crypto_sign_seed_keypair( $keyseed ), 0, 64 );
    }

    if( $sodium && function_exists( 'sodium_crypto_sign_seed_keypair' ) )
    {
        return substr( sodium_crypto_sign_seed_keypair( $keyseed ), 0, 64 );
    }

    $edsk = to_ord( $sodium ? sha512( $keyseed ) : $keyseed, 32 );
    $edsk[0] &= 248;
    $edsk[31] &= 127;
    $edsk[31] |= 64;

    $edpk = pack( scalarbase( $edsk ) );
    return $keyseed . to_chr( $edpk, 32 );
}
