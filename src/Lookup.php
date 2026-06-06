<?php

declare(strict_types=1);

namespace Switon\Authorizing;

use Switon\Core\Attribute\Autowired;

/**
 * Config-backed role permission lookup for authorization checks.
 *
 * Reads role mappings from the autowired <code>$permissions</code> configuration.
 * Permission CSV stays unexpanded for fast Authorization substring checks.
 *
 * @see \Switon\Authorizing\LookupInterface
 * @see \Switon\Authorizing\Authorization
 */
class Lookup implements LookupInterface
{
    /** @var array<string, string> Role => permission CSV (no spaces, no list expansion). */
    #[Autowired] protected array $permissions = [];

    /**
     * {@inheritDoc}
     */
    public function getPermissions(string $role): ?string
    {
        return $this->permissions[$role] ?? null;
    }
}
