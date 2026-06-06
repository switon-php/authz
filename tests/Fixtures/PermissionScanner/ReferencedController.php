<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Fixtures\PermissionScanner;

use Switon\Authorizing\Attribute\Authorize;

#[Authorize(Authorize::AUTHENTICATED)]
class ReferencedController
{
    #[GetMapping('/referenced/index')]
    public function indexAction(): void
    {
    }

    #[Authorize('@index')]
    #[PostMapping('/referenced/delete')]
    public function deleteAction(): void
    {
    }
}
