<?php

declare(strict_types=1);

namespace Switon\Authorizing\Event;

use JsonSerializable;
use Switon\Eventing\Attribute\EventLevel;
use Switon\Eventing\Severity;

/**
 * Event emitted when authorization enforcement denies access.
 *
 * Log category: <code>switon.authorizing.authorization.denied</code>
 *
 * @see \Switon\Authorizing\Authorization::authorize()
 * @see \Switon\Authorizing\Event\AuthorizationGranted
 */
#[EventLevel(Severity::INFO)]
class AuthorizationDenied implements JsonSerializable
{
    /**
     * @param string $operation Permission code (for example <code>admin::create-user</code> or <code>rbac.role::index</code>) or handler reference
     *                          (<code>FQCN::method</code>)
     * @param int $status HTTP status code (<code>401</code> or <code>403</code>)
     * @param array<string> $roles Roles used for the decision
     */
    public function __construct(
        public string $operation,
        public int    $status,
        public array  $roles,
    ) {
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return [
            'operation' => $this->operation,
            'status' => $this->status,
            'roles' => $this->roles,
        ];
    }
}
