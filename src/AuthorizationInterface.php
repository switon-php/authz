<?php

declare(strict_types=1);

namespace Switon\Authorizing;

use Switon\Http\Exception\ForbiddenException;
use Switon\Http\Exception\UnauthorizedException;

/**
 * HTTP-facing authorization contract for permission checks and request enforcement.
 *
 * Guidance: Use can() for service-layer checks; use authorize() only at HTTP request boundaries.
 *
 * Road-signs:
 * - can() accepts either a permission code or a valid handler reference
 * - invalid handler references fail closed
 * - authorize() emits decision events before raising HTTP exceptions
 * - 401 vs 403 is split by exception type
 * - handler references stay on the normalized handler-id path
 *
 * @see \Switon\Authorizing\Authorization
 * @see \Switon\Authorizing\Attribute\Authorize
 * @see \Switon\Authorizing\LookupInterface
 * @see \Switon\Authorizing\VoterInterface
 * @see \Switon\Authorizing\Event\AuthorizationGranted
 * @see \Switon\Authorizing\Event\AuthorizationDenied
 * @see \Switon\Routing\HandlerIdInterface
 * @see \Switon\Http\Event\RequestAuthorizing
 * @see \Switon\Http\Exception\UnauthorizedException
 * @see \Switon\Http\Exception\ForbiddenException
 */
interface AuthorizationInterface
{
    /**
     * Returns whether the given operation can be performed.
     *
     * Guidance: Only a valid <code>FQCN::method</code> is treated as a handler reference;
     * all other inputs stay on the permission-code path.
     *
     * @param string $operation Permission code (for example <code>admin::create-user</code> or <code>rbac.role::index</code>) or handler reference
     *                          (<code>FQCN::method</code>); invalid handler references are denied
     * @param array<string>|null $roles Explicit roles; <code>null</code> means current identity roles
     */
    public function can(string $operation, ?array $roles = null): bool;

    /**
     * Enforces one HTTP operation and raises HTTP exceptions on failure.
     *
     * Decision events are dispatched before the exception boundary.
     *
     * @param string $operation Permission code (for example <code>admin::create-user</code> or <code>rbac.role::index</code>) or handler reference
     *                          (<code>FQCN::method</code>)
     * @param array<string>|null $roles Explicit roles; <code>null</code> means current identity roles
     *
     * @throws UnauthorizedException User is not authenticated
     * @throws ForbiddenException User is authenticated but denied
     */
    public function authorize(string $operation, ?array $roles = null): void;
}
