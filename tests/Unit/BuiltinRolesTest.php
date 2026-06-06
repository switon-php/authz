<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Unit;

use Switon\Authorizing\Attribute\Authorize;
use Switon\Authorizing\BuiltinRoles;
use Switon\Authorizing\Tests\TestCase;

class BuiltinRolesTest extends TestCase
{
    public function testAllReturnsCanonicalBuiltinRoleKeys(): void
    {
        $builtinRoles = new BuiltinRoles();

        $this->assertSame([
            Authorize::ANONYMOUS,
            Authorize::AUTHENTICATED,
            Authorize::SUPERUSER,
        ], $builtinRoles->all());
    }
}
