<?php

declare(strict_types=1);

namespace Switon\Authorizing;

/**
 * Request/coroutine-local cache for authorization permission lookups.
 *
 * Guidance: Store cached <code>,permission,</code> CSV by role for one request/coroutine only.
 *
 * Road-signs:
 * - owned by Authorization::getContext()
 * - filled by Authorization::getPermissionCsv()
 * - read by Authorization::matchesPermission()
 *
 * @see \Switon\Authorizing\Authorization
 * @see \Switon\Authorizing\LookupInterface
 */
class AuthorizationContext
{
    /** @var array<string, string> Cached role permissions in <code>,permission,permission,</code> format. */
    public array $permissions = [];
}
