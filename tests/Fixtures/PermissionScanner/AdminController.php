<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Fixtures\PermissionScanner;

use Switon\Authorizing\Attribute\Authorize;

#[Authorize(Authorize::SUPERUSER)]
class AdminController
{
    #[GetMapping('/admin/dashboard')]
    public function dashboardAction(): void
    {
    }

    #[PostMapping('/admin/users')]
    public function createUserAction(): void
    {
    }

    public function helperMethod(): void
    {
    }
}
