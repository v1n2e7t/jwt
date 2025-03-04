<?php
namespace v1n2e7t\JWT\Signer;

use InvalidArgumentException;
use v1n2e7t\JWT\Keys;
use PHPUnit\Framework\TestCase;
use const OPENSSL_ALGO_SHA256;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;

final class RsaTest extends TestCase
{
    use Keys;

    /**
     * @test
     *
     * @covers \v1n2e7t\JWT\Signer\Rsa::createHash
     * @covers \v1n2e7t\JWT\Signer\Rsa::validateKey
     * @covers \v1n2e7t\JWT\Signer\Rsa::getKeyType
     * @covers \v1n2e7t\JWT\Signer\OpenSSL
     * @covers \v1n2e7t\JWT\Signer\BaseSigner
     *
     * @uses \v1n2e7t\JWT\Signer\Key
     * @uses \v1n2e7t\JWT\Signature
     */
    public function createHashShouldReturnAValidOpensslSignature()
    {
        $payload = 'testing';

        $signer    = $this->getSigner();
        $signature = $signer->sign($payload, self::$rsaKeys['private']);

        $publicKey = openssl_pkey_get_public(self::$rsaKeys['public']->getContent());
        self::assertInternalType('resource', $publicKey);
        self::assertSame(1, openssl_verify($payload, $signature, $publicKey, OPENSSL_ALGO_SHA256));
    }

    /**
     * @test
     *
     * @covers \v1n2e7t\JWT\Signer\Rsa::createHash
     * @covers \v1n2e7t\JWT\Signer\Rsa::validateKey
     * @covers \v1n2e7t\JWT\Signer\Rsa::getKeyType
     * @covers \v1n2e7t\JWT\Signer\OpenSSL
     * @covers \v1n2e7t\JWT\Signer\BaseSigner
     *
     * @uses \v1n2e7t\JWT\Signer\Key
     */
    public function createHashShouldRaiseAnExceptionWhenKeyIsInvalid()
    {
        $key = <<<KEY
-----BEGIN RSA PRIVATE KEY-----
MGECAQACEQC4MRKSVsq5XnRBrJoX6+rnAgMBAAECECO8SZkgw6Yg66A6SUly/3kC
CQDtPXZtCQWJuwIJAMbBu17GDOrFAggopfhNlFcjkwIIVjb7G+U0/TECCEERyvxP
TWdN
-----END RSA PRIVATE KEY-----
KEY;

        $signer = $this->getSigner();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('There was an error while creating the signature');

        $signer->sign('testing', new Key($key));
    }

    /**
     * @test
     *
     * @covers \v1n2e7t\JWT\Signer\Rsa::createHash
     * @covers \v1n2e7t\JWT\Signer\Rsa::validateKey
     * @covers \v1n2e7t\JWT\Signer\OpenSSL
     * @covers \v1n2e7t\JWT\Signer\BaseSigner
     *
     * @uses \v1n2e7t\JWT\Signer\Key
     */
    public function createHashShouldRaiseAnExceptionWhenKeyIsNotParseable()
    {
        $signer = $this->getSigner();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('It was not possible to parse your key');

        $signer->sign('testing', new Key('blablabla'));
    }

    /**
     * @test
     *
     * @covers \v1n2e7t\JWT\Signer\Rsa::createHash
     * @covers \v1n2e7t\JWT\Signer\Rsa::validateKey
     * @covers \v1n2e7t\JWT\Signer\Rsa::getKeyType
     * @covers \v1n2e7t\JWT\Signer\OpenSSL
     * @covers \v1n2e7t\JWT\Signer\BaseSigner
     *
     * @uses \v1n2e7t\JWT\Signer\Key
     */
    public function createHashShouldRaiseAnExceptionWhenKeyTypeIsNotRsa()
    {
        $signer = $this->getSigner();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('This key is not compatible with this signer');

        $signer->sign('testing', self::$ecdsaKeys['private']);
    }

    /**
     * @test
     *
     * @covers \v1n2e7t\JWT\Signer\Rsa::doVerify
     * @covers \v1n2e7t\JWT\Signer\Rsa::validateKey
     * @covers \v1n2e7t\JWT\Signer\Rsa::getKeyType
     * @covers \v1n2e7t\JWT\Signer\OpenSSL
     * @covers \v1n2e7t\JWT\Signer\BaseSigner
     *
     * @uses \v1n2e7t\JWT\Signer\Key
     */
    public function doVerifyShouldReturnTrueWhenSignatureIsValid()
    {
        $payload    = 'testing';
        $privateKey = openssl_pkey_get_private(self::$rsaKeys['private']->getContent());
        self::assertInternalType('resource', $privateKey);

        $signature = '';
        openssl_sign($payload, $signature, $privateKey, OPENSSL_ALGO_SHA256);

        $signer = $this->getSigner();

        self::assertTrue($signer->verify($signature, $payload, self::$rsaKeys['public']));
    }

    /**
     * @test
     *
     * @covers \v1n2e7t\JWT\Signer\Rsa::doVerify
     * @covers \v1n2e7t\JWT\Signer\Rsa::validateKey
     * @covers \v1n2e7t\JWT\Signer\OpenSSL
     * @covers \v1n2e7t\JWT\Signer\BaseSigner
     *
     * @uses \v1n2e7t\JWT\Signer\Key
     */
    public function doVerifyShouldRaiseAnExceptionWhenKeyIsNotParseable()
    {
        $signer = $this->getSigner();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('It was not possible to parse your key');

        $signer->verify('testing', 'testing', new Key('blablabla'));
    }

    /**
     * @test
     *
     * @covers \v1n2e7t\JWT\Signer\Rsa::doVerify
     * @covers \v1n2e7t\JWT\Signer\Rsa::validateKey
     * @covers \v1n2e7t\JWT\Signer\OpenSSL
     * @covers \v1n2e7t\JWT\Signer\BaseSigner
     *
     * @uses \v1n2e7t\JWT\Signer\Key
     */
    public function doVerifyShouldRaiseAnExceptionWhenKeyTypeIsNotRsa()
    {
        $signer = $this->getSigner();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('It was not possible to parse your key');

        $signer->verify('testing', 'testing', self::$ecdsaKeys['private']);
    }

    private function getSigner()
    {
        $signer = $this->getMockForAbstractClass(Rsa::class);

        $signer->method('getAlgorithm')
               ->willReturn(OPENSSL_ALGO_SHA256);

        $signer->method('getAlgorithmId')
               ->willReturn('RS256');

        return $signer;
    }
}
