<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Fixtures\TestClasses;

use Switon\Authorizing\Attribute\Authorize;

#[Authorize([Authorize::SUPERUSER, 'editor'])]
class CustomRoleController
{
    public function editAction(): void
    {
    }
}
