<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Fixtures\TestClasses;

use Switon\Authorizing\Attribute\Authorize;

#[Authorize('editor')]
class MethodReferenceMergesClassRolesController
{
    /**
     * Method-level reference-only attribute delegates effective roles to the class-level #[Authorize].
     */
    #[Authorize('@catalog.meta')]
    public function refOnlyAction(): void
    {
    }
}
