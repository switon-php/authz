<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Fixtures\TestClasses;

use Switon\Authorizing\Attribute\Authorize;

#[Authorize(Authorize::AUTHENTICATED)]
class MixedAuthorizeController
{
    #[Authorize(Authorize::SUPERUSER)]
    public function adminOnlyAction(): void
    {
    }

    public function userAction(): void
    {
    }
}
