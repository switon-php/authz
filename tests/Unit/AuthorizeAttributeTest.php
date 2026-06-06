<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Unit;

use Switon\Authorizing\Attribute\Authorize;
use Switon\Core\Exception\InvalidArgumentException;
use Switon\Authorizing\Tests\TestCase;

class AuthorizeAttributeTest extends TestCase
{
    public function testAuthorizeAttributeCanBeInstantiated(): void
    {
        $attribute = new Authorize('superuser');

        $this->assertSame(['superuser'], $attribute->getRoles());
        $this->assertNull($attribute->getReference());
    }

    public function testAuthorizeAttributeCanBeInstantiatedWithMultipleRoles(): void
    {
        $attribute = new Authorize(['superuser', 'editor']);

        $this->assertSame(['superuser', 'editor'], $attribute->getRoles());
        $this->assertNull($attribute->getReference());
    }

    public function testAuthorizeAttributeAcceptsExplicitAssignableOverride(): void
    {
        $attribute = new Authorize(['editor'], assignable: false);

        $this->assertSame(['editor'], $attribute->getRoles());
        $this->assertFalse($attribute->isAssignable());
    }

    public function testIsAssignableDefaultsTrueForGrantableRoles(): void
    {
        $attribute = new Authorize(['editor']);

        $this->assertTrue($attribute->isAssignable());
    }

    public function testIsAssignableFalseForIdentityStateRolesEvenWhenOverrideTrue(): void
    {
        $attribute = new Authorize(Authorize::AUTHENTICATED, assignable: true);

        $this->assertFalse($attribute->isAssignable());
    }

    public function testHasExplicitAssignableWhenConstructorPassesAssignable(): void
    {
        $this->assertFalse((new Authorize(['editor']))->hasExplicitAssignable());
        $this->assertTrue((new Authorize(['editor'], assignable: false))->hasExplicitAssignable());
        $this->assertTrue((new Authorize(Authorize::AUTHENTICATED, assignable: true))->hasExplicitAssignable());
    }

    public function testAuthorizeAttributeRejectsAnonymousWhenCombinedWithOtherRoles(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('anonymous must be used as a standalone role in #[Authorize].');

        new Authorize([Authorize::ANONYMOUS, 'editor']);
    }

    public function testAuthorizeAttributeRejectsAuthenticatedWhenCombinedWithOtherRoles(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('authenticated must be used as a standalone role in #[Authorize].');

        new Authorize([Authorize::AUTHENTICATED, Authorize::SUPERUSER]);
    }

    public function testAuthorizeAttributeAcceptsSinglePermissionReferenceString(): void
    {
        $attribute = new Authorize('@edit');

        $this->assertSame([], $attribute->getRoles());
        $this->assertSame('edit', $attribute->getReference());
    }

    public function testAuthorizeAttributeRejectsEmptyPermissionReference(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Authorize permission reference must not be empty.');

        new Authorize('@');
    }

    public function testAuthorizeAttributeRejectsPermissionReferenceInsideRoleArray(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Authorize permission reference must be passed as a single string, not inside a role array.'
        );

        new Authorize(['editor', '@edit']);
    }
}
