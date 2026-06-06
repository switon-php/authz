<?php

declare(strict_types=1);

namespace Switon\Authorizing;

use ReflectionMethod;

/**
 * Extension point for custom authorization decisions before the default flow.
 *
 * Guidance: Decide from normalized permission code; use handler only as context.
 *
 * Road-signs:
 * - called from Authorization::can()
 * - first non-null vote wins
 * - null falls through to default checks
 *
 * @see \Switon\Authorizing\Authorization::can()
 * @see \Switon\Authorizing\AuthorizationInterface
 */
interface VoterInterface
{
    /**
     * Votes on one normalized permission before default authorization checks.
     *
     * @param string $permission Normalized permission code (for example <code>admin::create-user</code> or <code>rbac.role::index</code>)
     * @param ReflectionMethod|null $handler Reflected handler when the original operation was a valid <code>FQCN::method</code>
     *
     * @return bool|null <code>true</code> grant; <code>false</code> deny; <code>null</code> abstain
     */
    public function vote(string $permission, ?ReflectionMethod $handler): ?bool;
}
