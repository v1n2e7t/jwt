<?php
/**
 * This file is part of v1n2e7t\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace v1n2e7t\JWT;

use v1n2e7t\JWT\Claim\Factory as ClaimFactory;
use v1n2e7t\JWT\Parsing\Encoder;
use v1n2e7t\JWT\Signer\Key;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class BuilderTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var Encoder|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $encoder;

    /**
     * @var ClaimFactory|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $claimFactory;

    /**
     * @var Claim|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $defaultClaim;

    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        $this->encoder = $this->createMock(Encoder::class);
        $this->claimFactory = $this->createMock(ClaimFactory::class);
        $this->defaultClaim = $this->createMock(Claim::class);

        $this->claimFactory->expects($this->any())
                           ->method('create')
                           ->willReturn($this->defaultClaim);
    }

    /**
     * @return Builder
     */
    private function createBuilder()
    {
        return new Builder($this->encoder, $this->claimFactory);
    }

    /**
     * @test
     *
     * @covers v1n2e7t\JWT\Builder::__construct
     */
    public function constructMustInitializeTheAttributes()
    {
        $builder = $this->createBuilder();

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        $this->assertAttributeEquals([], 'claims', $builder);
        $this->assertAttributeSame($this->encoder, 'encoder', $builder);
        $this->assertAttributeSame($this->claimFactory, 'claimFactory', $builder);
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::permittedFor
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function permittedForMustChangeTheAudClaim()
    {
        $builder = $this->createBuilder();
        $builder->permittedFor('test');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        $this->assertAttributeEquals(['aud' => $this->defaultClaim], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::permittedFor
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function permittedForCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->permittedFor('test', true);

        $this->assertAttributeEquals(['aud' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'aud' => $this->defaultClaim],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::permittedFor
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function permittedForMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->permittedFor('test'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::expiresAt
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function expiresAtMustChangeTheExpClaim()
    {
        $builder = $this->createBuilder();
        $builder->expiresAt('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        $this->assertAttributeEquals(['exp' => $this->defaultClaim], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::expiresAt
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function expiresAtCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->expiresAt('2', true);

        $this->assertAttributeEquals(['exp' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'exp' => $this->defaultClaim],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::expiresAt
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function expiresAtMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->expiresAt('2'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::identifiedBy
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function identifiedByMustChangeTheJtiClaim()
    {
        $builder = $this->createBuilder();
        $builder->identifiedBy('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        $this->assertAttributeEquals(['jti' => $this->defaultClaim], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::identifiedBy
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function identifiedByCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->identifiedBy('2', true);

        $this->assertAttributeEquals(['jti' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'jti' => $this->defaultClaim],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::identifiedBy
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function identifiedByMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->identifiedBy('2'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::issuedAt
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function issuedAtMustChangeTheIatClaim()
    {
        $builder = $this->createBuilder();
        $builder->issuedAt('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        $this->assertAttributeEquals(['iat' => $this->defaultClaim], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::issuedAt
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function issuedAtCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->issuedAt('2', true);

        $this->assertAttributeEquals(['iat' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'iat' => $this->defaultClaim],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::issuedAt
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function issuedAtMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->issuedAt('2'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::issuedBy
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function issuedByMustChangeTheIssClaim()
    {
        $builder = $this->createBuilder();
        $builder->issuedBy('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        $this->assertAttributeEquals(['iss' => $this->defaultClaim], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::issuedBy
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function issuedByCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->issuedBy('2', true);

        $this->assertAttributeEquals(['iss' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'iss' => $this->defaultClaim],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::issuedBy
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function issuedByMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->issuedBy('2'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::canOnlyBeUsedAfter
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function canOnlyBeUsedAfterMustChangeTheNbfClaim()
    {
        $builder = $this->createBuilder();
        $builder->canOnlyBeUsedAfter('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        $this->assertAttributeEquals(['nbf' => $this->defaultClaim], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::canOnlyBeUsedAfter
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function canOnlyBeUsedAfterCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->canOnlyBeUsedAfter('2', true);

        $this->assertAttributeEquals(['nbf' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'nbf' => $this->defaultClaim],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::canOnlyBeUsedAfter
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function canOnlyBeUsedAfterMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->canOnlyBeUsedAfter('2'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::relatedTo
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function relatedToMustChangeTheSubClaim()
    {
        $builder = $this->createBuilder();
        $builder->relatedTo('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        $this->assertAttributeEquals(['sub' => $this->defaultClaim], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::relatedTo
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function relatedToCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->relatedTo('2', true);

        $this->assertAttributeEquals(['sub' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'sub' => $this->defaultClaim],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     *
     * @covers v1n2e7t\JWT\Builder::relatedTo
     * @covers v1n2e7t\JWT\Builder::setRegisteredClaim
     */
    public function relatedToMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->relatedTo('2'));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     *
     * @covers v1n2e7t\JWT\Builder::withClaim
     */
    public function withClaimMustConfigureTheGivenClaim()
    {
        $builder = $this->createBuilder();
        $builder->withClaim('userId', 2);

        $this->assertAttributeEquals(['userId' => $this->defaultClaim], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     *
     * @covers v1n2e7t\JWT\Builder::withClaim
     */
    public function withClaimMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->withClaim('userId', 2));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     *
     * @covers v1n2e7t\JWT\Builder::withHeader
     */
    public function withHeaderMustConfigureTheGivenClaim()
    {
        $builder = $this->createBuilder();
        $builder->withHeader('userId', 2);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'userId' => $this->defaultClaim],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     *
     * @covers v1n2e7t\JWT\Builder::withHeader
     */
    public function withHeaderMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->withHeader('userId', 2));
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::getToken
     * @uses v1n2e7t\JWT\Token
     *
     * @covers v1n2e7t\JWT\Builder::sign
     */
    public function signMustConfigureSignerAndKey()
    {
        $signer = $this->createMock(Signer::class);

        $builder = $this->createBuilder();
        $builder->sign($signer, 'test');

        $this->assertAttributeSame($signer, 'signer', $builder);
        $this->assertAttributeEquals(new Key('test'), 'key', $builder);
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::getToken
     * @uses v1n2e7t\JWT\Token
     *
     * @covers v1n2e7t\JWT\Builder::sign
     */
    public function signMustKeepAFluentInterface()
    {
        $signer = $this->createMock(Signer::class);
        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->sign($signer, 'test'));

        return $builder;
    }

    /**
     * @test
     *
     * @depends signMustKeepAFluentInterface
     *
     * @covers v1n2e7t\JWT\Builder::unsign
     */
    public function unsignMustRemoveTheSignerAndKey(Builder $builder)
    {
        $builder->unsign();

        $this->assertAttributeSame(null, 'signer', $builder);
        $this->assertAttributeSame(null, 'key', $builder);
    }

    /**
     * @test
     *
     * @depends signMustKeepAFluentInterface
     *
     * @covers v1n2e7t\JWT\Builder::unsign
     */
    public function unsignMustKeepAFluentInterface(Builder $builder)
    {
        $this->assertSame($builder, $builder->unsign());
    }

    /**
     * @test
     *
     * @uses v1n2e7t\JWT\Builder::__construct
     * @uses v1n2e7t\JWT\Builder::withClaim
     * @uses v1n2e7t\JWT\Token
     *
     * @covers v1n2e7t\JWT\Builder::getToken
     */
    public function getTokenMustReturnANewTokenWithCurrentConfiguration()
    {
        $signer = $this->createMock(Signer::class);
        $signature = $this->createMock(Signature::class);

        $signer->method('sign')->willReturn($signature);

        $this->encoder->expects($this->exactly(2))
                      ->method('jsonEncode')
                      ->withConsecutive([['typ'=> 'JWT', 'alg' => 'none']], [['test' => $this->defaultClaim]])
                      ->willReturnOnConsecutiveCalls('1', '2');

        $this->encoder->expects($this->exactly(3))
                      ->method('base64UrlEncode')
                      ->withConsecutive(['1'], ['2'], [$signature])
                      ->willReturnOnConsecutiveCalls('1', '2', '3');

        $builder = $this->createBuilder()->withClaim('test', 123);
        $token = $builder->getToken($signer, new Key('testing'));

        $this->assertAttributeEquals(['1', '2', '3'], 'payload', $token);
        $this->assertAttributeEquals($token->getHeaders(), 'headers', $builder);
        $this->assertAttributeEquals($token->getClaims(), 'claims', $builder);
        $this->assertAttributeSame($signature, 'signature', $token);
    }
}
