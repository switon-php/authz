<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Fixtures\TestClasses;

use Switon\Authorizing\Attribute\Authorize;

#[Authorize(Authorize::AUTHENTICATED)]
class UserController
{
    public function indexAction(): void
    {
    }

    public function profileAction(): void
    {
    }

    #[Authorize(Authorize::ANONYMOUS)]
    public function publicAction(): void
    {
    }
}
