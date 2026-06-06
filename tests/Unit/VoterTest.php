<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Unit;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use ReflectionMethod;
use Switon\Authorizing\Attribute\Authorize;
use Switon\Authorizing\Authorization;
use Switon\Authorizing\AuthorizationContext;
use Switon\Authorizing\LookupInterface;
use Switon\Authorizing\VoterInterface;
use Switon\Core\ContextManagerInterface;
use Switon\Http\RequestInterface;
use Switon\Principal\IdentityInterface;
use Switon\Routing\HandlerIdInterface;
use Switon\Authorizing\Tests\TestCase;

#[AllowMockObjectsWithoutExpectations]
class VoterTest extends TestCase
{
    private int $voterIdSequence = 0;

    /**
     * @return list<string>
     */
    private function registerVoters(object ...$voters): array
    {
        $ids = [];

        foreach ($voters as $voter) {
            $id = 'test.voter.' . ++$this->voterIdSequence;
            $this->container->set($id, $voter);
            $ids[] = $id;
        }

        return $ids;
    }

    public function testAuthorizationInvokesVoterAndShortCircuitsGrant(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([]);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->never())->method('getPermissions');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->method('getId')->willReturn('voter::handled');

        $voter = new class () implements VoterInterface {
            public array $seen = [];

            public function vote(string $permission, ?ReflectionMethod $handler): ?bool
            {
                $this->seen[] = [
                    'permission' => $permission,
                    'handler' => $handler,
                ];

                if ($permission === 'voter::handled') {
                    return true;
                }

                return null;
            }
        };

        $voterIds = $this->registerVoters($voter);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
            'voters' => $voterIds,
        ]);

        $handler = self::class . '::dummyHandler';

        // Act
        $result = $authorization->can($handler);

        // Assert
        $this->assertTrue($result, 'Voter should be able to grant access and short-circuit default logic');
        $this->assertCount(1, $voter->seen, 'Voter should be called exactly once');
        $this->assertSame('voter::handled', $voter->seen[0]['permission']);
        $this->assertInstanceOf(ReflectionMethod::class, $voter->seen[0]['handler']);
        $this->assertSame($handler, $voter->seen[0]['handler']->getDeclaringClass()->getName() . '::' . $voter->seen[0]['handler']->getName());
    }

    public function testAuthorizationDeniesWhenNoVotersOrPermissions(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([]);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->method('getPermissions')->willReturn('');

        $handlerId = $this->createMock(HandlerIdInterface::class);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
            // Explicitly inject no voters
            'voters' => [],
        ]);

        // Act
        $result = $authorization->can('blog::view');

        // Assert
        $this->assertFalse($result, 'With no permissions and no voters, access should be denied');
    }

    public function testVoterReceivesNullHandlerForPermissionString(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([]);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->never())->method('getPermissions');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->never())->method('getId');

        $voter = new class () implements VoterInterface {
            public ?ReflectionMethod $seenHandler = null;

            public function vote(string $permission, ?ReflectionMethod $handler): ?bool
            {
                $this->seenHandler = $handler;
                return false;
            }
        };

        $voterIds = $this->registerVoters($voter);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
            'voters' => $voterIds,
        ]);

        // Act
        $result = $authorization->can('blog::view');

        // Assert
        $this->assertFalse($result);
        $this->assertNull($voter->seenHandler);
    }

    public function testMalformedFqcnHandlerSkipsVotersAndReturnsFalse(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([Authorize::AUTHENTICATED]);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->never())->method('getPermissions');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->never())->method('getId');

        $voter = new class () implements VoterInterface {
            public int $called = 0;

            public function vote(string $permission, ?ReflectionMethod $handler): ?bool
            {
                $this->called++;
                return true;
            }
        };

        $voterIds = $this->registerVoters($voter);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
            'voters' => $voterIds,
        ]);

        // Act
        $result = $authorization->can('App\\Controller\\MissingController::missingAction');

        // Assert
        $this->assertFalse($result);
        $this->assertSame(0, $voter->called);
    }

    public function testVoterNullDecisionFallsBackToDefaultPermissionChecks(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn(['editor']);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->once())
            ->method('getPermissions')
            ->with('editor')
            ->willReturn('blog::view');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->never())->method('getId');

        $voter = new class () implements VoterInterface {
            public int $calls = 0;

            public function vote(string $permission, ?ReflectionMethod $handler): ?bool
            {
                $this->calls++;
                return null;
            }
        };

        $voterIds = $this->registerVoters($voter);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
            'voters' => $voterIds,
        ]);

        // Act
        $result = $authorization->can('blog::view');

        // Assert
        $this->assertTrue($result);
        $this->assertSame(1, $voter->calls, 'Voter should be evaluated before default permission checks');
    }

    public function testMultipleVotersStopAtFirstNonNullDecision(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([]);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->never())->method('getPermissions');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->never())->method('getId');

        $first = new class () implements VoterInterface {
            public int $calls = 0;

            public function vote(string $permission, ?ReflectionMethod $handler): ?bool
            {
                $this->calls++;
                return null;
            }
        };

        $second = new class () implements VoterInterface {
            public int $calls = 0;

            public function vote(string $permission, ?ReflectionMethod $handler): ?bool
            {
                $this->calls++;
                return false;
            }
        };

        $third = new class () implements VoterInterface {
            public int $calls = 0;

            public function vote(string $permission, ?ReflectionMethod $handler): ?bool
            {
                $this->calls++;
                return true;
            }
        };

        $voterIds = $this->registerVoters($first, $second, $third);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
            'voters' => $voterIds,
        ]);

        // Act
        $result = $authorization->can('blog::view');

        // Assert
        $this->assertFalse($result);
        $this->assertSame(1, $first->calls);
        $this->assertSame(1, $second->calls);
        $this->assertSame(0, $third->calls, 'Voters after first non-null decision must not run');
    }

    public function testNonFqcnOperationWithDoubleColonIsHandledAsPermissionString(): void
    {
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $contextManager->method('getContext')->willReturn(new AuthorizationContext());

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([]);

        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->never())->method('getPermissions');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->never())->method('getId');

        $voter = new class () implements VoterInterface {
            public ?ReflectionMethod $seenHandler = null;
            public ?string $seenPermission = null;

            public function vote(string $permission, ?ReflectionMethod $handler): ?bool
            {
                $this->seenPermission = $permission;
                $this->seenHandler = $handler;
                return false;
            }
        };

        $voterIds = $this->registerVoters($voter);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $this->createMock(RequestInterface::class),
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
            'voters' => $voterIds,
        ]);

        $result = $authorization->can('module::action');

        $this->assertFalse($result);
        $this->assertSame('module::action', $voter->seenPermission);
        $this->assertNull($voter->seenHandler);
    }

    public static function dummyHandler(): void
    {
        // Used for handler-based tests
    }
}
