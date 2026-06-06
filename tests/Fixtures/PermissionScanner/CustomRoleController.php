<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Fixtures\PermissionScanner;

use Switon\Authorizing\Attribute\Authorize;

class CustomRoleController
{
    #[Authorize('editor', assignable: false)]
    #[GetMapping('/custom/edit')]
    public function editAction(): void
    {
    }
}
