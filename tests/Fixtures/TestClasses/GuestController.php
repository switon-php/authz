<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Fixtures\TestClasses;

use Switon\Authorizing\Attribute\Authorize;

#[Authorize(Authorize::ANONYMOUS)]
class GuestController
{
    public function indexAction(): void
    {
    }
}
