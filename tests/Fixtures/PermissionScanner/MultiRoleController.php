<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Fixtures\PermissionScanner;

use Switon\Authorizing\Attribute\Authorize;

#[Authorize(Authorize::AUTHENTICATED)]
class MultiRoleController
{
    #[GetMapping('/multi/index')]
    public function indexAction(): void
    {
    }

    #[GetMapping('/multi/settings')]
    public function settingsAction(): void
    {
    }
}
