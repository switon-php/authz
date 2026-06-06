<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Fixtures\PermissionScanner;

use Switon\Authorizing\Attribute\Authorize;

#[Authorize(Authorize::ANONYMOUS)]
class GuestController
{
    #[GetMapping('/guest/index')]
    public function indexAction(): void
    {
    }
}
