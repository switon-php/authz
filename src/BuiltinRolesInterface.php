<?php

declare(strict_types=1);

namespace Switon\Authorizing;

/**
 * Describes the built-in role names and identity-state markers used by authz semantics.
 *
 * Guidance: Keep built-in role semantics here so consumers like RBAC do not couple to annotation constants directly.
 *
 * @see \Switon\Authorizing\Attribute\Authorize
 * @see \Switon\Authorizing\BuiltinRoles
 */
interface BuiltinRolesInterface
{
    /**
     * Return all built-in role names exposed by authz.
     *
     * @return string[]
     */
    public function all(): array;
}
