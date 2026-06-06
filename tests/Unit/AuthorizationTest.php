<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Unit;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use Psr\EventDispatcher\EventDispatcherInterface;
use Switon\Authorizing\Attribute\Authorize;
use Switon\Authorizing\Authorization;
use Switon\Authorizing\AuthorizationContext;
use Switon\Authorizing\Event\AuthorizationDenied;
use Switon\Authorizing\Event\AuthorizationGranted;
use Switon\Authorizing\LookupInterface;
use Switon\Authorizing\Tests\Fixtures\TestClasses;
use Switon\Core\ContextManagerInterface;
use Switon\Http\Event\RequestAuthorizing;
use Switon\Http\Exception\ForbiddenException;
use Switon\Http\Exception\UnauthorizedException;
use Switon\Http\RequestInterface;
use Switon\Principal\IdentityInterface;
use Switon\Routing\HandlerIdInterface;
use Switon\Authorizing\Tests\TestCase;
use ReflectionMethod;

#[AllowMockObjectsWithoutExpectations]
class AuthorizationTest extends TestCase
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

    public function testCanUsesExplicitRolesInsteadOfIdentityRoles(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        // If identity roles were used, SUPERUSER would short-circuit to true.
        $identity->method('getRoles')->willReturn([Authorize::SUPERUSER]);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->never())
            ->method('getPermissions');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->never())->method('getId');

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        // Act
        $result = $authorization->can('blog::view', []);

        // Assert
        $this->assertFalse($result, 'Explicit roles argument should override identity roles');
    }

    public function testCanWithGuestRolesDoesNotUseLookupAndReturnsFalse(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([]);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->never())
            ->method('getPermissions');

        $handlerId = $this->createMock(HandlerIdInterface::class);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        // Act
        $first = $authorization->can('blog::view');
        $second = $authorization->can('blog::view');

        // Assert
        $this->assertFalse($first);
        $this->assertFalse($second);
    }

    public function testCanWithInvalidHandlerStringReturnsFalse(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);

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
        ]);

        // Act
        $result = $authorization->can('App\\Controller\\UserController', []);

        // Assert
        $this->assertFalse($result);
    }

    public function testCanWithInvalidHandlerStringHasNoDispatchSideEffect(): void
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

        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->expects($this->never())->method('dispatch');

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
            'eventDispatcher' => $eventDispatcher,
        ]);

        // Act
        $result = $authorization->can('App\\Controller\\MissingController::missingAction');

        // Assert
        $this->assertFalse($result);
    }

    public function testPermissionLikeStringWithColonDoesNotUseHandlerIdNormalization(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn(['editor']);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->method('getPermissions')
            ->willReturnCallback(static fn (string $role): ?string => $role === 'editor' ? 'blog::view' : '');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->never())->method('getId');

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        // Act
        $result = $authorization->can('blog::view');

        // Assert
        $this->assertTrue($result);
    }

    public function testPermissionLikeStringWithBackslashDoesNotUseHandlerIdNormalization(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn(['editor']);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->method('getPermissions')
            ->willReturnCallback(static fn (string $role): ?string => $role === 'editor' ? 'tenant\\report' : '');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->never())->method('getId');

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        // Act
        $result = $authorization->can('tenant\\report');

        // Assert
        $this->assertTrue($result);
    }

    public function testMalformedFqcnHandlerStringReturnsFalseWithoutLookup(): void
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

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        // Act
        $result = $authorization->can('App\\Controller\\MissingController::missingAction');

        // Assert
        $this->assertFalse($result);
    }

    public function testExistingControllerWithMissingActionReturnsFalseWithoutLookup(): void
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

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        // Act
        $result = $authorization->can(TestClasses\UserController::class . '::missingAction');

        // Assert
        $this->assertFalse($result);
    }

    public function testCanWithAuthorizeAttributeAndUserRoleGrantsAccess(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);

        $handlerId = $this->createMock(HandlerIdInterface::class);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        $handler = TestClasses\UserController::class . '::indexAction';

        // Act
        $result = $authorization->can($handler, [Authorize::AUTHENTICATED]);

        // Assert
        $this->assertTrue($result);
    }

    public function testCanWithUserAuthorizeAttributeDeniesGuest(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([]);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);

        $handlerId = $this->createMock(HandlerIdInterface::class);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        $handler = TestClasses\UserController::class . '::indexAction';

        // Act
        $result = $authorization->can($handler);

        // Assert
        $this->assertFalse($result);
    }

    public function testCanWithGuestAuthorizeAttributeGrantsGuest(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([]);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);

        $handlerId = $this->createMock(HandlerIdInterface::class);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        $handler = TestClasses\GuestController::class . '::indexAction';

        // Act
        $result = $authorization->can($handler);

        // Assert
        $this->assertTrue($result);
    }

    public function testMethodLevelAnonymousAuthorizeOverridesClassAuthenticatedForGuest(): void
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
        $handlerId->expects($this->once())
            ->method('getId')
            ->with(TestClasses\UserController::class, 'publicAction')
            ->willReturn('user::public');

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        $handler = TestClasses\UserController::class . '::publicAction';

        // Act
        $result = $authorization->can($handler);

        // Assert
        $this->assertTrue($result);
    }

    public function testCanWithCustomRoleUsesRolePermissions(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->once())
            ->method('getPermissions')
            ->with('editor')
            ->willReturn('blog::edit');

        $handlerId = $this->createMock(HandlerIdInterface::class);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        // Act
        $result = $authorization->can('blog::edit', ['editor']);

        // Assert
        $this->assertTrue($result);
    }

    public function testCanCachesLookupPermissionsPerRoleAcrossRepeatedChecks(): void
    {
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->once())
            ->method('getPermissions')
            ->with('editor')
            ->willReturn('blog::edit,blog::view');

        $handlerId = $this->createMock(HandlerIdInterface::class);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        $this->assertTrue($authorization->can('blog::edit', ['editor']));
        $this->assertTrue($authorization->can('blog::view', ['editor']));
    }

    public function testCustomRoleAuthorizeAttributeGrantsMatchingRole(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->method('getId')->willReturn('custom::edit');

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        $handler = TestClasses\CustomRoleController::class . '::editAction';

        // Act
        $resultAdmin = $authorization->can($handler, [Authorize::SUPERUSER]);
        $resultEditor = $authorization->can($handler, ['editor']);
        $resultViewer = $authorization->can($handler, ['viewer']);
        $resultGuest = $authorization->can($handler, []);

        // Assert
        // SUPERUSER grants via global rule, editor grants via attribute, others denied
        $this->assertTrue($resultAdmin);
        $this->assertTrue($resultEditor);
        $this->assertFalse($resultViewer);
        $this->assertFalse($resultGuest);
    }

    public function testMethodAuthorizeOverridesClassAuthorize(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);

        $handlerId = $this->createMock(HandlerIdInterface::class);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        $adminHandler = TestClasses\MixedAuthorizeController::class . '::adminOnlyAction';
        $userHandler = TestClasses\MixedAuthorizeController::class . '::userAction';

        // Act & Assert
        // adminOnlyAction: SUPERUSER attribute present, ensure superuser passes
        $this->assertTrue($authorization->can($adminHandler, [Authorize::SUPERUSER]));

        // userAction: inherits class-level AUTHENTICATED, so authenticated passes and unauthenticated denied
        $this->assertTrue($authorization->can($userHandler, [Authorize::AUTHENTICATED]));
        $this->assertFalse($authorization->can($userHandler, []));
    }

    public function testCanAdminRoleAlwaysGrantsWithoutPermissionsLookup(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([Authorize::SUPERUSER]);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->never())
            ->method('getPermissions');

        $handlerId = $this->createMock(HandlerIdInterface::class);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        // Act
        $result = $authorization->can('any::permission');

        // Assert
        $this->assertTrue($result);
    }

    public function testEmptyAuthorizeAttributeDoesNotDelegateToDbForGuest(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([]);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        // Current behavior: for handler strings with #[Authorize] (empty roles) and unauthenticated user
        // (no roles), Authorization denies before consulting LookupInterface.
        // This expectation documents that design.
        $permissionsLookup->expects($this->never())
            ->method('getPermissions');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->method('getId')->willReturn('delegated::index');

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        $handler = TestClasses\DelegatedAuthorizeController::class . '::indexAction';

        // Act
        $result = $authorization->can($handler);

        // Assert - currently denied for unauthenticated user even if lookup would grant
        $this->assertFalse($result);
    }

    public function testEmptyAuthorizeAttributeDelegatesToDbForUserRole(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->method('getPermissions')
            ->willReturnCallback(static function (string $role): ?string {
                return $role === 'editor' ? 'delegated::index' : '';
            });

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->method('getId')->willReturn('delegated::index');

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        $handler = TestClasses\DelegatedAuthorizeController::class . '::indexAction';

        // Act
        $result = $authorization->can($handler, ['editor']);

        // Assert
        $this->assertTrue($result);
    }

    public function testCanUsesClassAuthorizeWhenMethodHasReferenceOnly(): void
    {
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->never())->method('getPermissions');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->method('getId')
            ->with(TestClasses\MethodReferenceMergesClassRolesController::class, 'refOnlyAction')
            ->willReturn('merge::ref-only');

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $this->createMock(RequestInterface::class),
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        $handler = TestClasses\MethodReferenceMergesClassRolesController::class . '::refOnlyAction';

        $this->assertTrue($authorization->can($handler, ['editor']));
    }

    public function testHandlerWithoutAuthorizeAttributeFallsBackToPermissionLookup(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn(['viewer']);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->once())
            ->method('getPermissions')
            ->with('viewer')
            ->willReturn('plain::view');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->once())
            ->method('getId')
            ->with(TestClasses\PlainController::class, 'viewAction')
            ->willReturn('plain::view');

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        $handler = TestClasses\PlainController::class . '::viewAction';

        // Act
        $result = $authorization->can($handler);

        // Assert
        $this->assertTrue($result);
    }

    public function testAuthorizeRaisesUnauthorizedForGuestWhenDenied(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([]);

        $request = $this->createMock(RequestInterface::class);
        $request->method('verb')->willReturn('GET');
        $request->method('url')->willReturn('/protected');
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
        ]);

        $this->expectException(UnauthorizedException::class);

        // Act
        $authorization->authorize('blog::view');
    }

    public function testAuthorizeDispatchesGrantedEventWhenAccessIsGranted(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn(['editor']);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->method('getPermissions')
            ->willReturnCallback(static fn (string $role): ?string => $role === 'editor' ? 'blog::view' : '');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->expects($this->once())
            ->method('dispatch')
            ->with($this->callback(static function (object $event): bool {
                return $event instanceof AuthorizationGranted
                    && $event->operation === 'blog::view'
                    && $event->roles === ['editor'];
            }))
            ->willReturnArgument(0);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
            'eventDispatcher' => $eventDispatcher,
        ]);

        // Act - should not throw
        $authorization->authorize('blog::view');
    }

    public function testAuthorizeWithExplicitRolesDispatchesGrantedEventWithExplicitRoles(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        // Explicit roles must override identity roles in granted event payload.
        $identity->method('getRoles')->willReturn([Authorize::SUPERUSER]);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->once())
            ->method('getPermissions')
            ->with('editor')
            ->willReturn('blog::view');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->expects($this->once())
            ->method('dispatch')
            ->with($this->callback(static function (object $event): bool {
                return $event instanceof AuthorizationGranted
                    && $event->operation === 'blog::view'
                    && $event->roles === ['editor'];
            }))
            ->willReturnArgument(0);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
            'eventDispatcher' => $eventDispatcher,
        ]);

        // Act - should not throw
        $authorization->authorize('blog::view', ['editor']);
    }

    public function testCanDoesNotGrantForPermissionPrefixCollision(): void
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
            ->willReturn('post::edit-all');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->never())->method('getId');

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        // Act
        $result = $authorization->can('post::edit');

        // Assert
        $this->assertFalse($result);
    }

    public function testCanSkipsBuiltinIdentityStateRolesAndUsesCustomRolePermissions(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->once())
            ->method('getPermissions')
            ->with('editor')
            ->willReturn('blog::edit');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->never())->method('getId');

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        // Act
        $withAuthenticated = $authorization->can('blog::edit', [Authorize::AUTHENTICATED, 'editor']);
        $withAnonymous = $authorization->can('blog::edit', [Authorize::ANONYMOUS, 'editor']);

        // Assert
        $this->assertTrue($withAuthenticated);
        $this->assertTrue($withAnonymous);
    }

    public function testVoterDenyOverridesSuperuserRole(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([Authorize::SUPERUSER]);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->never())->method('getPermissions');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->never())->method('getId');

        $voter = new class () implements \Switon\Authorizing\VoterInterface {
            public int $calls = 0;

            public function vote(string $permission, ?ReflectionMethod $handler): ?bool
            {
                $this->calls++;
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
        $result = $authorization->can('blog::edit');

        // Assert
        $this->assertFalse($result);
        $this->assertSame(1, $voter->calls);
    }

    public function testAuthorizeDispatchesDeniedEventWith401ForGuest(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([]);

        $request = $this->createMock(RequestInterface::class);
        $request->method('verb')->willReturn('GET');
        $request->method('url')->willReturn('/private');
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->method('getPermissions')->willReturn('');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->expects($this->once())
            ->method('dispatch')
            ->with($this->callback(static function (object $event): bool {
                return $event instanceof AuthorizationDenied
                    && $event->operation === 'blog::view'
                    && $event->status === 401
                    && $event->roles === [];
            }))
            ->willReturnArgument(0);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
            'eventDispatcher' => $eventDispatcher,
        ]);

        $this->expectException(UnauthorizedException::class);

        // Act
        $authorization->authorize('blog::view');
    }

    public function testAuthorizeDispatchesDeniedEventWith403ForAuthenticatedUser(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([Authorize::AUTHENTICATED]);

        $request = $this->createMock(RequestInterface::class);
        $request->method('verb')->willReturn('POST');
        $request->method('url')->willReturn('/private');
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->method('getPermissions')->willReturn('');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->expects($this->once())
            ->method('dispatch')
            ->with($this->callback(static function (object $event): bool {
                return $event instanceof AuthorizationDenied
                    && $event->operation === 'blog::view'
                    && $event->status === 403
                    && $event->roles === [Authorize::AUTHENTICATED];
            }))
            ->willReturnArgument(0);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
            'eventDispatcher' => $eventDispatcher,
        ]);

        $this->expectException(ForbiddenException::class);

        // Act
        $authorization->authorize('blog::view');
    }

    public function testAuthorizeWithExplicitGuestRolesRaisesUnauthorized(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([Authorize::SUPERUSER]);

        $request = $this->createMock(RequestInterface::class);
        $request->method('verb')->willReturn('GET');
        $request->method('url')->willReturn('/protected');
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
        ]);

        $this->expectException(UnauthorizedException::class);

        // Act
        $authorization->authorize('blog::view', []);
    }

    public function testAuthorizeWithExplicitGuestRolesDispatchesDeniedEventWith401(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        // Explicit roles should override identity roles in event payload and status branch.
        $identity->method('getRoles')->willReturn([Authorize::SUPERUSER]);

        $request = $this->createMock(RequestInterface::class);
        $request->method('verb')->willReturn('GET');
        $request->method('url')->willReturn('/protected');
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->method('getPermissions')->willReturn('');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->expects($this->once())
            ->method('dispatch')
            ->with($this->callback(static function (object $event): bool {
                return $event instanceof AuthorizationDenied
                    && $event->operation === 'blog::view'
                    && $event->status === 401
                    && $event->roles === [];
            }))
            ->willReturnArgument(0);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
            'eventDispatcher' => $eventDispatcher,
        ]);

        $this->expectException(UnauthorizedException::class);

        // Act
        $authorization->authorize('blog::view', []);
    }

    public function testAuthorizeRaisesForbiddenForAuthenticatedUserWhenDenied(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([Authorize::AUTHENTICATED]);

        $request = $this->createMock(RequestInterface::class);
        $request->method('verb')->willReturn('GET');
        $request->method('url')->willReturn('/protected');
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
        ]);

        $this->expectException(ForbiddenException::class);

        // Act
        $authorization->authorize('blog::view');
    }

    public function testAuthorizeWithExplicitRolesRaisesForbidden(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([]);

        $request = $this->createMock(RequestInterface::class);
        $request->method('verb')->willReturn('GET');
        $request->method('url')->willReturn('/protected');
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
        ]);

        $this->expectException(ForbiddenException::class);

        // Act
        $authorization->authorize('blog::view', ['editor']);
    }

    public function testAuthorizeWithExplicitRolesDispatchesDeniedEventWith403(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([]);

        $request = $this->createMock(RequestInterface::class);
        $request->method('verb')->willReturn('GET');
        $request->method('url')->willReturn('/protected');
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->method('getPermissions')->willReturn('');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->expects($this->once())
            ->method('dispatch')
            ->with($this->callback(static function (object $event): bool {
                return $event instanceof AuthorizationDenied
                    && $event->operation === 'blog::view'
                    && $event->status === 403
                    && $event->roles === ['editor'];
            }))
            ->willReturnArgument(0);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
            'eventDispatcher' => $eventDispatcher,
        ]);

        $this->expectException(ForbiddenException::class);

        // Act
        $authorization->authorize('blog::view', ['editor']);
    }

    public function testOnAuthorizingBridgesEventToAuthorizeFlow(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn(['editor']);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->method('getPermissions')
            ->willReturnCallback(static fn (string $role): ?string => $role === 'editor' ? 'user::index' : '');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->once())
            ->method('getId')
            ->with(TestClasses\UserController::class, 'indexAction')
            ->willReturn('user::index');

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        $method = new ReflectionMethod(TestClasses\UserController::class, 'indexAction');
        $event = new RequestAuthorizing($method);

        // Act / Assert - should not throw
        $authorization->onAuthorizing($event);
        $this->assertTrue(true);
    }

    public function testAuthorizeWithHandlerOperationDispatchesGrantedEventUsingOriginalOperation(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([]);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->once())
            ->method('getPermissions')
            ->with('editor')
            ->willReturn('plain::view');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->once())
            ->method('getId')
            ->with(TestClasses\PlainController::class, 'viewAction')
            ->willReturn('plain::view');

        $operation = TestClasses\PlainController::class . '::viewAction';
        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->expects($this->once())
            ->method('dispatch')
            ->with($this->callback(static function (object $event) use ($operation): bool {
                return $event instanceof AuthorizationGranted
                    && $event->operation === $operation
                    && $event->roles === ['editor'];
            }))
            ->willReturnArgument(0);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
            'eventDispatcher' => $eventDispatcher,
        ]);

        // Act
        $authorization->authorize($operation, ['editor']);
    }

    public function testCanCachesPermissionLookupAcrossRolesBetweenCalls(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->exactly(2))
            ->method('getPermissions')
            ->willReturnCallback(static function (string $role): ?string {
                return match ($role) {
                    'viewer' => '',
                    'editor' => 'blog::edit',
                    default => '',
                };
            });

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->never())->method('getId');

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        // Act
        $first = $authorization->can('blog::edit', ['viewer', 'editor']);
        $second = $authorization->can('blog::edit', ['viewer', 'editor']);

        // Assert
        $this->assertTrue($first);
        $this->assertTrue($second);
    }

    public function testOnAuthorizingDispatchesDeniedEventWith401ForGuest(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([]);

        $request = $this->createMock(RequestInterface::class);
        $request->method('verb')->willReturn('GET');
        $request->method('url')->willReturn('/private');

        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->never())->method('getPermissions');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->once())
            ->method('getId')
            ->with(TestClasses\UserController::class, 'indexAction')
            ->willReturn('user::index');

        $operation = TestClasses\UserController::class . '::indexAction';
        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->expects($this->once())
            ->method('dispatch')
            ->with($this->callback(static function (object $event) use ($operation): bool {
                return $event instanceof AuthorizationDenied
                    && $event->operation === $operation
                    && $event->status === 401
                    && $event->roles === [];
            }))
            ->willReturnArgument(0);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
            'eventDispatcher' => $eventDispatcher,
        ]);

        $method = new ReflectionMethod(TestClasses\UserController::class, 'indexAction');
        $event = new RequestAuthorizing($method);

        $this->expectException(UnauthorizedException::class);

        // Act
        $authorization->onAuthorizing($event);
    }

    public function testOnAuthorizingDispatchesDeniedEventWith403ForAuthenticatedUser(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn(['editor']);

        $request = $this->createMock(RequestInterface::class);
        $request->method('verb')->willReturn('POST');
        $request->method('url')->willReturn('/private');

        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->once())
            ->method('getPermissions')
            ->with('editor')
            ->willReturn('');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->once())
            ->method('getId')
            ->with(TestClasses\PlainController::class, 'viewAction')
            ->willReturn('plain::view');

        $operation = TestClasses\PlainController::class . '::viewAction';
        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->expects($this->once())
            ->method('dispatch')
            ->with($this->callback(static function (object $event) use ($operation): bool {
                return $event instanceof AuthorizationDenied
                    && $event->operation === $operation
                    && $event->status === 403
                    && $event->roles === ['editor'];
            }))
            ->willReturnArgument(0);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
            'eventDispatcher' => $eventDispatcher,
        ]);

        $method = new ReflectionMethod(TestClasses\PlainController::class, 'viewAction');
        $event = new RequestAuthorizing($method);

        $this->expectException(ForbiddenException::class);

        // Act
        $authorization->onAuthorizing($event);
    }

    public function testAuthorizeWithHandlerOperationDispatchesDeniedEventUsingOriginalOperation(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn(['editor']);

        $request = $this->createMock(RequestInterface::class);
        $request->method('verb')->willReturn('GET');
        $request->method('url')->willReturn('/users');

        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->once())
            ->method('getPermissions')
            ->with('editor')
            ->willReturn('');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->once())
            ->method('getId')
            ->with(TestClasses\PlainController::class, 'viewAction')
            ->willReturn('plain::view');

        $operation = TestClasses\PlainController::class . '::viewAction';
        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->expects($this->once())
            ->method('dispatch')
            ->with($this->callback(static function (object $event) use ($operation): bool {
                return $event instanceof AuthorizationDenied
                    && $event->operation === $operation
                    && $event->status === 403
                    && $event->roles === ['editor'];
            }))
            ->willReturnArgument(0);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
            'eventDispatcher' => $eventDispatcher,
        ]);

        $this->expectException(ForbiddenException::class);

        // Act
        $authorization->authorize($operation);
    }

    public function testCanWithExistingControllerAndMissingMethodSkipsVoter(): void
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

        $voter = new class () implements \Switon\Authorizing\VoterInterface {
            public int $calls = 0;

            public function vote(string $permission, ?ReflectionMethod $handler): ?bool
            {
                $this->calls++;
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
        $result = $authorization->can(TestClasses\PlainController::class . '::missingAction');

        // Assert
        $this->assertFalse($result);
        $this->assertSame(0, $voter->calls);
    }

    public function testCanResultIsIndependentOfRoleOrder(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->exactly(2))
            ->method('getPermissions')
            ->willReturnCallback(static function (string $role): ?string {
                return match ($role) {
                    'viewer' => '',
                    'editor' => 'blog::edit',
                    default => '',
                };
            });

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->never())->method('getId');

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        // Act
        $editorFirst = $authorization->can('blog::edit', ['editor', 'viewer']);
        $viewerFirst = $authorization->can('blog::edit', ['viewer', 'editor']);

        // Assert
        $this->assertTrue($editorFirst);
        $this->assertTrue($viewerFirst);
    }

    public function testCanWithWhitespaceInLookupCsvDoesNotGrantWithoutExactToken(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn(['editor']);

        $request = $this->createMock(RequestInterface::class);
        $permissionsLookup = $this->createMock(LookupInterface::class);
        // Intentionally includes a leading space before blog::edit
        $permissionsLookup->expects($this->once())
            ->method('getPermissions')
            ->with('editor')
            ->willReturn('blog::view, blog::edit');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->never())->method('getId');

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
        ]);

        // Act
        $result = $authorization->can('blog::edit');

        // Assert
        $this->assertFalse($result);
    }

    public function testOnAuthorizingAllowsAnonymousMethodForGuestWithoutLookup(): void
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
        $handlerId->expects($this->once())
            ->method('getId')
            ->with(TestClasses\UserController::class, 'publicAction')
            ->willReturn('user::public');

        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $operation = TestClasses\UserController::class . '::publicAction';
        $eventDispatcher->expects($this->once())
            ->method('dispatch')
            ->with($this->callback(static function (object $event) use ($operation): bool {
                return $event instanceof AuthorizationGranted
                    && $event->operation === $operation
                    && $event->roles === [];
            }))
            ->willReturnArgument(0);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
            'eventDispatcher' => $eventDispatcher,
        ]);

        $method = new ReflectionMethod(TestClasses\UserController::class, 'publicAction');
        $event = new RequestAuthorizing($method);

        // Act / Assert - anonymous method should pass for guest
        $authorization->onAuthorizing($event);
        $this->assertTrue(true);
    }

    public function testOnAuthorizingVoterDenyOverridesSuperuserAndDispatches403(): void
    {
        // Arrange
        $contextManager = $this->createMock(ContextManagerInterface::class);
        $context = new AuthorizationContext();
        $contextManager->method('getContext')->willReturn($context);

        $identity = $this->createMock(IdentityInterface::class);
        $identity->method('getRoles')->willReturn([Authorize::SUPERUSER]);

        $request = $this->createMock(RequestInterface::class);
        $request->method('verb')->willReturn('GET');
        $request->method('url')->willReturn('/admin');

        $permissionsLookup = $this->createMock(LookupInterface::class);
        $permissionsLookup->expects($this->never())->method('getPermissions');

        $handlerId = $this->createMock(HandlerIdInterface::class);
        $handlerId->expects($this->once())
            ->method('getId')
            ->with(TestClasses\PlainController::class, 'viewAction')
            ->willReturn('plain::view');

        $voter = new class () implements \Switon\Authorizing\VoterInterface {
            public int $calls = 0;

            public function vote(string $permission, ?ReflectionMethod $handler): ?bool
            {
                $this->calls++;
                return false;
            }
        };

        $operation = TestClasses\PlainController::class . '::viewAction';
        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->expects($this->once())
            ->method('dispatch')
            ->with($this->callback(static function (object $event) use ($operation): bool {
                return $event instanceof AuthorizationDenied
                    && $event->operation === $operation
                    && $event->status === 403
                    && $event->roles === [Authorize::SUPERUSER];
            }))
            ->willReturnArgument(0);

        $voterIds = $this->registerVoters($voter);

        /** @var Authorization $authorization */
        $authorization = $this->make(Authorization::class, [
            'contextManager' => $contextManager,
            'identity' => $identity,
            'request' => $request,
            'lookup' => $permissionsLookup,
            'handlerId' => $handlerId,
            'eventDispatcher' => $eventDispatcher,
            'voters' => $voterIds,
        ]);

        $method = new ReflectionMethod(TestClasses\PlainController::class, 'viewAction');
        $event = new RequestAuthorizing($method);

        $this->expectException(ForbiddenException::class);
        $this->expectExceptionMessage('Access denied');
        $this->assertSame(0, $voter->calls);

        // Act
        try {
            $authorization->onAuthorizing($event);
        } finally {
            $this->assertSame(1, $voter->calls);
        }
    }
}
