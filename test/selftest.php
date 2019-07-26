<?php

require __DIR__ . '/../vendor/autoload.php';
use deemru\Curve25519;
use deemru\ABCode;

if( !function_exists( 'random_bytes' ) ){ function random_bytes( $size ){ $rnd = ''; while( $size-- ) $rnd .= chr( mt_rand() ); return $rnd; } }
$sodium = function_exists( 'sodium_crypto_sign_detached' ) ? true : false;

$base58 = ABCode::base58();

$curve25519 = new Curve25519();
$msg = 'Hello, world!';

$privateKey = random_bytes( 32 );
$sig = $curve25519->sign( $msg, $privateKey );

$publicKey = $curve25519->getPublicKeyFromPrivateKey( $privateKey );
$verify = $curve25519->verify( $sig, $msg, $publicKey );

if( !$verify )
    exit( 1 );

class tester
{
    private $successful = 0;
    private $failed = 0;
    private $depth = 0;
    private $info = [];
    private $start = [];

    public function pretest( $info )
    {
        $this->info[$this->depth] = $info;
        $this->start[$this->depth] = microtime( true );
        if( !isset( $this->init ) )
            $this->init = $this->start[$this->depth];
        $this->depth++;
    }

    private function ms( $start )
    {
        $ms = ( microtime( true ) - $start ) * 1000;
        $ms = $ms > 100 ? round( $ms ) : $ms;
        $ms = sprintf( $ms > 10 ? ( $ms > 100 ? '%.00f' : '%.01f' ) : '%.02f', $ms );
        return $ms;
    }

    public function test( $cond )
    {
        $this->depth--;
        $ms = $this->ms( $this->start[$this->depth] );
        echo ( $cond ? 'SUCCESS: ' : 'ERROR:   ' ) . "{$this->info[$this->depth]} ($ms ms)\n";
        $cond ? $this->successful++ : $this->failed++;
    }

    public function finish()
    {
        $total = $this->successful + $this->failed;
        $ms = $this->ms( $this->init );
        echo "  TOTAL: {$this->successful}/$total ($ms ms)\n";
        sleep( 3 );

        if( $this->failed > 0 )
            exit( 1 );
    }
}

echo "   TEST: Curve25519\n";
$t = new tester();

// https://docs.wavesplatform.com/en/technical-details/cryptographic-practical-details.html

$privateKey = $base58->decode( '7VLYNhmuvAo5Us4mNGxWpzhMSdSSdEbEPFUDKSnA6eBv' );
$publicKey = $curve25519->getPublicKeyFromPrivateKey( $privateKey );

$t->pretest( 'getPublicKeyFromPrivateKey' );
{
    $publicKey = $curve25519->getPublicKeyFromPrivateKey( $privateKey );
    $t->test( $publicKey === $base58->decode( 'EENPV1mRhUD9gSKbcWt84cqnfSGQP5LkCu5gMBfAanYH' ) );
}

$t->pretest( 'verify (known)' );
{
    $msg = $base58->decode( 'Ht7FtLJBrnukwWtywum4o1PbQSNyDWMgb4nXR5ZkV78krj9qVt17jz74XYSrKSTQe6wXuPdt3aCvmnF5hfjhnd1gyij36hN1zSDaiDg3TFi7c7RbXTHDDUbRgGajXci8PJB3iJM1tZvh8AL5wD4o4DCo1VJoKk2PUWX3cUydB7brxWGUxC6mPxKMdXefXwHeB4khwugbvcsPgk8F6YB' );
    $sig = $base58->decode( '2mQvQFLQYJBe9ezj7YnAQFq7k9MxZstkrbcSKpLzv7vTxUfnbvWMUyyhJAc1u3vhkLqzQphKDecHcutUrhrHt22D' );
    $t->test( $curve25519->verify( $sig, $msg, $publicKey ) === true );
}

function flipsig_test( $t, $sig, $msg, $publicKey, $curve25519, $text, $sodium = true )
{
    $t->pretest( $text );
    $verify = false;
    for( $i = 0; $i < 64; $i++ )
    {
        $c = ord( $sig[$i] );
        for( $j = 0; $j < 8; $j++ )
        {
            if( !$sodium && mt_rand( 1, 3 ) > 1 )
                continue;
            $ctest = $c ^ ( 1 << $j );
            $sig[$i] = chr( $ctest );
            $verify = $verify || $curve25519->verify( $sig, $msg, $publicKey );
        }
        $sig[$i] = chr( $c );
    }

    $verify = $verify || !$curve25519->verify( $sig, $msg, $publicKey );
    $t->test( false === $verify );
}

function flipkey_test( $t, $sig, $msg, $publicKey, $curve25519, $text )
{
    $t->pretest( $text );
    $verify = false;
    for( $i = 0; $i < 32; $i++ )
    {
        $c = ord( $publicKey[$i] );
        for( $j = 0; $j < 8; $j++ )
        {
            $ctest = $c ^ ( 1 << $j );
            $publicKey[$i] = chr( $ctest );
            if( $i === 31 && $j === 7 )
                $verify = $verify || !$curve25519->verify( $sig, $msg, $publicKey );
            else
                $verify = $verify || $curve25519->verify( $sig, $msg, $publicKey );
        }
        $publicKey[$i] = chr( $c );
    }

    $verify = $verify || !$curve25519->verify( $sig, $msg, $publicKey );
    $t->test( false === $verify );
}

$R = null;
$sameR = 0;
for( $i = 1; $i <= 12; $i++ )
{
    $t->pretest( "sign/verify #$i" );
    {
        $sig = $curve25519->sign( $msg, $privateKey );
        $sameR |= isset( $R ) ? $R === substr( $sig, 0, 32 ) : 0;
        $R = substr( $sig, 0, 32 );
        $t->test( $curve25519->verify( $sig, $msg, $publicKey ) === true );
    }
}

$t->pretest( "sign/verify (same R not used)" );
$t->test( !$sameR );

$t->pretest( 'getSodiumPublicKeyFromPrivateKey' );
{
    $sodiumPublicKey = $curve25519->getSodiumPublicKeyFromPrivateKey( $privateKey );
    $t->test( $sodiumPublicKey !== $base58->decode( 'EENPV1mRhUD9gSKbcWt84cqnfSGQP5LkCu5gMBfAanYH' ) );
}

$R = null;
$sameR = 0;
for( $i = 1; $i <= 12; $i++ )
{
    $t->pretest( "sign/verify (sodium) #$i" );
    {
        $sig = $curve25519->sign_sodium( $msg, $privateKey );
        $sameR |= isset( $R ) ? $R === substr( $sig, 0, 32 ) : 0;
        $R = substr( $sig, 0, 32 );
        $t->test( $curve25519->verify( $sig, $msg, $sodiumPublicKey ) === true );
    }
}

if( defined( 'CURVE25519_SODIUM_SUPPORT' ) )
{
    $t->pretest( "sign/verify (sodium with ED25519_NONDETERMINISTIC)" );
    $t->test( !$sameR );
}
else if( $sameR )
{
    echo 'WARNING: sodium without ED25519_NONDETERMINISTIC' . PHP_EOL;
}

$t->pretest( "sign/verify (rseed) without define()" );
{
    $t->test( false === $curve25519->sign( $msg, $privateKey, '123' ) );
}

define( 'IREALLYKNOWWHAT_RSEED_MEANS', null );

unset( $R );
for( $i = 1; $i <= 12; $i++ )
{
    $t->pretest( "sign/verify (rseed) #$i" );
    {
        $msg .= $msg;
        $sig = $curve25519->sign( $msg, $privateKey, '123' );
        
        if( !isset( $R ) )
            $R = $curve25519->sign( null, $privateKey, '123' );

        $R_test = substr( $sig, 0, 32 ) === $R;
        $S_test = isset( $sig_saved ) ? substr( $sig, 32 ) !== substr( $sig_saved, 32 ) : true;

        $t->test( $curve25519->verify( $sig, $msg, $publicKey ) === true && $R_test && $S_test );
        $sig_saved = $sig;
    }
}

if( $sodium )
{
    $msg = random_bytes( 32 );
    $t->pretest( "12 signs" );
    $mt = microtime( true );
    for( $i = 1; $i <= 12; $i++ )
        $sig = $curve25519->sign( $msg, $privateKey );
    $mt = microtime( true ) - $mt;
    $t->test( $sig !== false );

    $t->pretest( "12 signs (sodium)" );
    $mt_sodium = microtime( true );
    for( $i = 1; $i <= 12; $i++ )
        $sig = $curve25519->sign_sodium( $msg, $privateKey );
    $mt_sodium = microtime( true ) - $mt_sodium;
    $t->test( $sig !== false );

    $x = intval( $mt / $mt_sodium );
    if( defined( 'CURVE25519_SODIUM_SUPPORT' ) )
    {
        $t->pretest( 'CURVE25519_SODIUM_SUPPORT' );
        $t->test( $x <= 1 );
    }
    else
    {
        $t->pretest( "sodium is {$x}x faster" );
        $t->test( $mt_sodium * 100 < $mt );
    }
}

$mt = microtime( true );
for( $i = 1; microtime( true ) - $mt < ( defined( 'CURVE25519_SODIUM_SUPPORT' ) ? 1.337 : 13.37 ); $i++ )
{
    $t->pretest( "sign/verify (complex) #$i" );

    $privateKey = random_bytes( 32 );
    $sodiumPrivateKey = $curve25519->getSodiumPrivateKeyFromPrivateKey( $privateKey );
    $sodiumPublicKey = $curve25519->getSodiumPublicKeyFromPrivateKey( $privateKey, mt_rand( 0, 1 ) == 1 );

    $strlen = mt_rand( 0, 16 );
    $msg = $strlen ? random_bytes( $strlen ) : '';

    $sig = $curve25519->sign( $msg, $sodiumPrivateKey );
    $verify = $curve25519->verify( $sig, $msg, $sodiumPublicKey );

    $sigso = $curve25519->sign_sodium( $msg, $privateKey );
    $verify = $curve25519->verify( $sigso, $msg, $sodiumPublicKey ) && $verify;

    $t->test( $verify );
}

{
    flipsig_test( $t, $sig, $msg, $sodiumPublicKey, $curve25519, 'signature bits flip (php)', $sodium );
    flipkey_test( $t, $sig, $msg, $sodiumPublicKey, $curve25519, 'publickey bits flip (php)' );
}

if( $sodium )
{
    flipsig_test( $t, $sigso, $msg, $sodiumPublicKey, $curve25519, 'signature bits flip (sodium)' );
    flipkey_test( $t, $sigso, $msg, $sodiumPublicKey, $curve25519, 'publickey bits flip (sodium)' );
}

$t->finish();
