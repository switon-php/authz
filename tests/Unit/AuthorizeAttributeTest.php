<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Unit;

use Switon\Authorizing\Attribute\Authorize;
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

    public function testAuthorizeAttributeTreatsEmptyPermissionReferenceAsEmptyString(): void
    {
        $attribute = new Authorize('@');

        $this->assertSame('', $attribute->getReference());
        $this->assertSame([], $attribute->getRoles());
    }

    public function testAuthorizeAttributeAllowsIdentityStateRolesCombinedWithOthers(): void
    {
        $anonymousMixed = new Authorize([Authorize::ANONYMOUS, 'editor']);
        $this->assertSame([Authorize::ANONYMOUS, 'editor'], $anonymousMixed->getRoles());
        $this->assertFalse($anonymousMixed->isAssignable());

        $authenticatedMixed = new Authorize([Authorize::AUTHENTICATED, Authorize::SUPERUSER]);
        $this->assertSame([Authorize::AUTHENTICATED, Authorize::SUPERUSER], $authenticatedMixed->getRoles());
        $this->assertFalse($authenticatedMixed->isAssignable());
    }

    public function testAuthorizeAttributeIgnoresPermissionReferenceInsideRoleArray(): void
    {
        $attribute = new Authorize(['editor', '@edit']);

        $this->assertSame(['editor'], $attribute->getRoles());
        $this->assertNull($attribute->getReference());
    }

    public function testAuthorizeAttributeAcceptsSinglePermissionReferenceString(): void
    {
        $attribute = new Authorize('@edit');

        $this->assertSame([], $attribute->getRoles());
        $this->assertSame('edit', $attribute->getReference());
    }
}
