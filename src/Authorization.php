<?php

declare(strict_types=1);

namespace Switon\Authorizing;

use Psr\EventDispatcher\EventDispatcherInterface;
use ReflectionAttribute;
use ReflectionMethod;
use Switon\Authorizing\Attribute\Authorize;
use Switon\Authorizing\Event\AuthorizationDenied;
use Switon\Authorizing\Event\AuthorizationGranted;
use Switon\Core\Attribute\Autowired;
use Switon\Core\ContextAware;
use Switon\Core\ContextManagerInterface;
use Switon\Eventing\Attribute\EventListener;
use Switon\Http\Event\RequestAuthorizing;
use Switon\Http\Exception\ForbiddenException;
use Switon\Http\Exception\UnauthorizedException;
use Switon\Principal\IdentityInterface;
use Switon\Routing\HandlerIdInterface;

use function explode;
use function in_array;
use function method_exists;
use function str_contains;

/**
 * Evaluates HTTP handler access from role attributes, permission lookup, and voter overrides.
 *
 * Combines <code>#[Authorize]</code> role rules with <code>LookupInterface</code>
 * permission mappings for final grant or deny decisions.
 *
 * Road-signs:
 * - event bridge from RequestAuthorizing
 * - handler normalization via HandlerIdInterface
 * - permission lookup via LookupInterface
 * - voters run before default checks
 * - deny decisions can override role grants, including SUPERUSER
 * - authorize() emits granted/denied events before raising HTTP exceptions
 *
 * @see \Switon\Authorizing\AuthorizationInterface
 * @see \Switon\Authorizing\VoterInterface
 * @see \Switon\Authorizing\AuthorizationContext
 * @see \Switon\Authorizing\Event\AuthorizationGranted
 * @see \Switon\Authorizing\Event\AuthorizationDenied
 * @see \Switon\Routing\HandlerIdInterface
 * @see \Switon\Http\Event\RequestAuthorizing
 * @see \Switon\Http\Exception\ForbiddenException
 * @see \Switon\Http\Exception\UnauthorizedException
 */
class Authorization implements AuthorizationInterface, ContextAware
{
    #[Autowired] protected ContextManagerInterface $contextManager;
    #[Autowired] protected IdentityInterface $identity;
    #[Autowired] protected LookupInterface $lookup;
    #[Autowired] protected HandlerIdInterface $handlerId;
    #[Autowired] protected EventDispatcherInterface $eventDispatcher;
    /** @var array<int, VoterInterface> Decision voters checked before default authorization logic. */
    #[Autowired(instances: true)] protected array $voters = [];

    /**
     * {@inheritDoc}
     */
    public function getContext(): AuthorizationContext
    {
        return $this->contextManager->getContext($this);
    }

    /**
     * Event bridge: authorizes the current controller action.
     */
    #[EventListener] public function onAuthorizing(RequestAuthorizing $event): void
    {
        $this->authorize($event->controller . '::' . $event->action);
    }

    /**
     * Returns cached <code>,permission,</code> CSV for one role.
     */
    protected function getPermissionCsv(string $role): string
    {
        $context = $this->getContext();

        if (!isset($context->permissions[$role])) {
            $permissions = $this->lookup->getPermissions($role) ?? '';
            return $context->permissions[$role] = ",$permissions,";
        } else {
            return $context->permissions[$role];
        }
    }

    /**
     * Resolves <code>#[Authorize]</code> from method first, then class.
     */
    protected function getAuthorize(string $controller, string $action): ?Authorize
    {
        $rMethod = new ReflectionMethod($controller, $action);
        $rClass = $rMethod->getDeclaringClass();

        $classAuthorize = ($rClass->getAttributes(Authorize::class, ReflectionAttribute::IS_INSTANCEOF)[0] ?? null)?->newInstance();
        $methodAuthorize = ($rMethod->getAttributes(Authorize::class, ReflectionAttribute::IS_INSTANCEOF)[0] ?? null)?->newInstance();

        if ($methodAuthorize === null) {
            return $classAuthorize;
        }

        if ($methodAuthorize->getRoles() === [] && $methodAuthorize->getReference() !== null && $classAuthorize !== null) {
            return $classAuthorize;
        }

        return $methodAuthorize;
    }

    /**
     * Fast exact permission check against cached role CSV.
     */
    protected function matchesPermission(string $permission, string $role): bool
    {
        return str_contains($this->getPermissionCsv($role), ",$permission,");
    }

    /**
     * {@inheritDoc}
     *
     * Guidance: Treat an operation as a handler reference only when it is a valid
     * <code>FQCN::method</code>; all other inputs stay on the permission fast path, and voter deny is evaluated
     * before role-level grants (including <code>SUPERUSER</code>).
     */
    public function can(string $operation, ?array $roles = null): bool
    {
        $roles = $roles ?? $this->identity->getRoles();

        $normalizedPermission = $operation;
        $controller = null;
        $action = null;

        // Fast shape check: only FQCN::method enters the handler normalization path.
        if (str_contains($operation, '\\') && str_contains($operation, '::')) {
            [$controller, $action] = explode('::', $operation, 2);
            if (!method_exists($controller, $action)) {
                return false;
            }
            $normalizedPermission = $this->handlerId->getId($controller, $action);
        }

        if ($this->voters !== []) {
            $method = $controller ? new ReflectionMethod($controller, $action) : null;

            foreach ($this->voters as $voter) {
                $decision = $voter->vote($normalizedPermission, $method);
                if ($decision !== null) {
                    return $decision;
                }
            }
        }

        if (in_array(Authorize::SUPERUSER, $roles, true)) {
            return true;
        }

        if ($controller !== null) {
            // NOTE: When an Authorize attribute is present and the current user has
            // no roles (unauthenticated), access is denied here unless the attribute
            // explicitly includes Authorize::ANONYMOUS. In that case, lookup permissions
            // are not consulted for unauthenticated users.
            if (($authorize = $this->getAuthorize($controller, $action)) !== null) {
                $authorizeRoles = $authorize->getRoles();
                if (in_array(Authorize::ANONYMOUS, $authorizeRoles, true)) {
                    return true;
                }

                if ($roles === []) {
                    return false;
                }

                if (in_array(Authorize::AUTHENTICATED, $authorizeRoles, true)) {
                    return true;
                }

                foreach ($authorizeRoles as $role) {
                    if (in_array($role, $roles, true)) {
                        return true;
                    }
                }
            }

            $operation = $normalizedPermission;
        }

        if ($roles === []) {
            return false;
        }

        foreach ($roles as $role) {
            if ($role === Authorize::ANONYMOUS || $role === Authorize::AUTHENTICATED) {
                continue;
            }

            if ($this->matchesPermission($operation, $role)) {
                return true;
            }
        }

        return false;
    }

    /**
     * {@inheritDoc}
     */
    public function authorize(string $operation, ?array $roles = null): void
    {
        $roles = $roles ?? $this->identity->getRoles();

        if ($this->can($operation, $roles)) {
            $this->eventDispatcher->dispatch(new AuthorizationGranted($operation, $roles));
            return;
        }

        if ($roles === []) {
            $this->eventDispatcher->dispatch(new AuthorizationDenied($operation, 401, $roles));
            UnauthorizedException::raise('Authentication required for {operation}', ['operation' => $operation]);
        } else {
            $this->eventDispatcher->dispatch(new AuthorizationDenied($operation, 403, $roles));
            ForbiddenException::raise('Access denied for {operation}', ['operation' => $operation]);
        }
    }
}
