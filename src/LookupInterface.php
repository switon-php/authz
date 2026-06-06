<?php

declare(strict_types=1);

namespace Switon\Authorizing;

/**
 * Contract for resolving permission mappings by role name.
 *
 * Guidance: Return a permission CSV string; this long-term contract keeps
 * Authorization on fast <code>,permission,</code> substring checks.
 *
 * Road-signs:
 * - called from Authorization::getPermissionCsv()
 * - CSV is the long-term contract for fast matching
 * - no spaces between permission codes
 *
 * @see \Switon\Authorizing\Lookup
 * @see \Switon\Authorizing\Authorization
 */
interface LookupInterface
{
    /**
     * Returns role permissions as a comma-separated string.
     *
     * @param string $role Role name
     *
     * @return string|null Permission CSV without spaces; return <code>null</code> when not configured
     */
    public function getPermissions(string $role): ?string;
}
