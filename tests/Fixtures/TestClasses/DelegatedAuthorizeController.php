<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Fixtures\TestClasses;

use Switon\Authorizing\Attribute\Authorize;

#[Authorize]
class DelegatedAuthorizeController
{
    public function indexAction(): void
    {
    }
}
