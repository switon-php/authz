<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Fixtures\PermissionScanner;

use Switon\Authorizing\Attribute\Authorize;

#[Authorize]
class DelegatedController
{
    #[GetMapping('/delegated/index')]
    public function indexAction(): void
    {
    }

    #[Authorize('editor')]
    #[GetMapping('/delegated/edit')]
    public function editAction(): void
    {
    }
}
