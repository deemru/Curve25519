<?php

require __DIR__ . '/../vendor/autoload.php';
use deemru\Curve25519;
use deemru\ABCode;

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

    public function pretest( $info )
    {
        $this->info = $info;
        $this->start = microtime( true );
        if( !isset( $this->init ) )
            $this->init = $this->start;
    }

    private function ms( &$start )
    {
        $ms = ( microtime( true ) - $start ) * 1000;
        $ms = $ms > 100 ? round( $ms ) : $ms;
        $ms = sprintf( $ms > 10 ? ( $ms > 100 ? '%.00f' : '%.01f' ) : '%.02f', $ms );
        $start = 0;
        return $ms;
    }

    public function test( $cond )
    {
        $ms = $this->ms( $this->start );
        echo ( $cond ? 'SUCCESS: ' : 'ERROR:   ' ) . "{$this->info} ($ms ms)\n";
        $cond ? $this->successful++ : $this->failed++;
    }

    public function finish()
    {
        $total = $this->successful + $this->failed;
        $ms = $this->ms( $this->init );
        echo "TOTAL:   {$this->successful}/$total ($ms ms)\n";
        sleep( 3 );

        if( $this->failed > 0 )
            exit( 1 );
    }
}

echo "TEST:    Curve25519\n";
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

for( $i = 1; $i <= 3; $i++ )
{
    $t->pretest( "sign/verify #$i" );
    {
        $sig = $curve25519->sign( $msg, $privateKey );
        $t->test( $curve25519->verify( $sig, $msg, $publicKey ) === true );
    }
}

$t->pretest( 'getSodiumPublicKeyFromPrivateKey' );
{
    $sodiumPublicKey = $curve25519->getSodiumPublicKeyFromPrivateKey( $privateKey );
    $t->test( $sodiumPublicKey !== $base58->decode( 'EENPV1mRhUD9gSKbcWt84cqnfSGQP5LkCu5gMBfAanYH' ) );
}

for( $i = 1; $i <= 3; $i++ )
{
    $t->pretest( "sign/verify (sodium) #$i" );
    {
        $sig = $curve25519->sign_sodium( $msg, $privateKey );
        $t->test( $curve25519->verify( $sig, $msg, $sodiumPublicKey ) === true );
    }
}

$t->pretest( "sign/verify (rseed) without define()" );
{
    $t->test( false === $curve25519->sign( $msg, $privateKey, '123' ) );
}

define( 'IREALLYKNOWWHAT_RSEED_MEANS', null );

for( $i = 1; $i <= 3; $i++ )
{
    $t->pretest( "sign/verify (rseed) #$i" );
    {
        $msg .= $msg;
        $sig = $curve25519->sign( $msg, $privateKey, '123' );

        $R_test = isset( $sig_saved ) ? substr( $sig, 0, 32 ) === substr( $sig_saved, 0, 32 ) : true;
        $S_test = isset( $sig_saved ) ? substr( $sig, 32 ) !== substr( $sig_saved, 32 ) : true;

        $t->test( $curve25519->verify( $sig, $msg, $publicKey ) === true && $R_test && $S_test );
        $sig_saved = $sig;
    }
}

{
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

    $x = intval( $mt / $mt_sodium ) . 'x';
    $t->pretest( "sodium is $x faster" );
    $t->test( $mt_sodium * 100 < $mt );
}

$mt = microtime( true );
for( $i = 1; microtime( true ) - $mt < 13.37; $i++ )
{
    $t->pretest( "sign/verify (complex) #$i" );

    $privateKey = random_bytes( 32 );
    $sodiumPrivateKey = $curve25519->getSodiumPrivateKeyFromPrivateKey( $privateKey );
    $sodiumPublicKey = $curve25519->getSodiumPublicKeyFromPrivateKey( $privateKey );

    $strlen = mt_rand( 0, 16 );
    $msg = $strlen ? random_bytes( $strlen ) : '';

    $sig = $curve25519->sign( $msg, $sodiumPrivateKey );
    $verify = $curve25519->verify( $sig, $msg, $sodiumPublicKey );
    $sig = $curve25519->sign_sodium( $msg, $privateKey );
    $verify = $curve25519->verify( $sig, $msg, $sodiumPublicKey ) && $verify;

    $t->test( $verify );
}

$t->finish();
