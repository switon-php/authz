<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Fixtures\PermissionScanner;

use Switon\Authorizing\Attribute\Authorize;

class PublicController
{
    #[GetMapping('/public/info')]
    public function infoAction(): void
    {
    }

    #[Authorize(Authorize::AUTHENTICATED, assignable: true)]
    #[GetMapping('/public/profile')]
    public function profileAction(): void
    {
    }
}
