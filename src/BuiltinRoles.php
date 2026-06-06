<?php

declare(strict_types=1);

namespace Switon\Authorizing;

use Switon\Authorizing\Attribute\Authorize;

/**
 * Default authz built-in role definitions.
 *
 * Use when framework code needs the canonical built-in roles without coupling to annotation constants at each consumer.
 *
 * @see \Switon\Authorizing\BuiltinRolesInterface
 * @see \Switon\Authorizing\Attribute\Authorize
 */
class BuiltinRoles implements BuiltinRolesInterface
{
    public function all(): array
    {
        return [
            Authorize::ANONYMOUS,
            Authorize::AUTHENTICATED,
            Authorize::SUPERUSER,
        ];
    }
}
