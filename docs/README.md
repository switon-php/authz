# Authorization Package {#authorization-package}
`switon/authz` gives controllers and services one shared authorization model based on **permission codes**. Application roles come from `Switon\Principal\IdentityInterface::getRoles()`; authentication stays outside this package.

**Key features:**
- **Access rules:** use `#[Authorize]` to protect controllers and methods.
- **One authorization API:** inject `AuthorizationInterface` for service checks.
- **Identity-state markers:** `Authorize::ANONYMOUS` and `Authorize::AUTHENTICATED`.
- **Superuser role:** `Authorize::SUPERUSER` is a built-in role key; identities that include it bypass later default checks unless a voter already denied access.
- **Role-to-permission mapping:** map application roles to permission codes with `LookupInterface`.
- **Context-based checks:** use `VoterInterface` when access depends on request or domain context.
- **Decision events:** authorization fires events when access is allowed or denied.

## Installation {#installation}

**Requirements:** `PHP 8.3+`

```bash
composer require switon/authz
```

## Quick Start {#quick-start}

Use `#[Authorize]` on controllers and `AuthorizationInterface` in services.

```php
use Switon\Authorizing\Attribute\Authorize;
use Switon\Authorizing\AuthorizationInterface;
use Switon\Core\Attribute\Autowired;

#[Authorize(Authorize::AUTHENTICATED)]
class AccountController
{
    #[Authorize(Authorize::ANONYMOUS)]
    public function loginAction(): array
    {
        return ['ok' => true];
    }

    public function profileAction(): array
    {
        return ['ok' => true];
    }
}

class OrderService
{
    #[Autowired] protected AuthorizationInterface $authorization;

    public function cancel(int $orderId): void
    {
        $this->authorization->authorize('order::cancel');
    }
}
```

`can()` returns `true` or `false`. `authorize()` raises HTTP exceptions and emits events.

## Core Concepts {#core-concepts}

### Attribute-First Rules {#attribute-first-rules}

- Put `#[Authorize]` on the class to set the default, then put it on a method to override that one method.
- A method attribute overrides the class default.
- If a method argument is a **permission reference** (a string that starts with `@`, for example `@edit`), authz records it as reference metadata instead of a role list.
- The `assignable` flag only affects **permission-scan metadata** (catalogs and RBAC UIs), not runtime authorization checks.
- Strings such as `admin::create-user` are permission codes used by controllers and services.
- Use `FQCN::method` when authz needs to point at one specific controller method. It must be a full class-and-method reference.
- An empty `#[Authorize]` keeps the handler in the authorization flow for signed-in users.
- `@reference` values help permission scanning and catalogs. Runtime checks still resolve through handler ids, class or method attributes, and normal permission lookup.

### Identity States {#identity-states}

- Use these to distinguish public access from authenticated access:
  - `Authorize::ANONYMOUS` for public access
  - `Authorize::AUTHENTICATED` for any authenticated user

### Superuser Role {#superuser-role}

- `Authorize::SUPERUSER` is a privileged role key.
- Identity roles containing it get the global bypass after voters abstain or grant.

### Service Checks {#service-checks}

- Use `AuthorizationInterface::can()` when denial is a normal branch.
- Use `AuthorizationInterface::authorize()` when denial should become `401` or `403`.
- The roles argument overrides `IdentityInterface::getRoles()`.
- `authorize()` emits `AuthorizationGranted` on success and `AuthorizationDenied` on failure.

### Role-to-Permission Mapping {#permission-lookup}

Use `LookupInterface` when application roles should map to permission codes.

- Keep codes exact.
- Do not add spaces.
- Do not put `anonymous` or `authenticated` in lookup config.

### Voters {#voters}

Use `VoterInterface` for request or domain context such as ownership, tenant, or IP checks.
- Return values mean:
  - `true` grants access and stops further voter checks
  - `false` denies access and stops further voter checks
  - `null` abstains and lets the default checks continue
- The first non-null vote wins.
- Voters run before the built-in role checks, including `Authorize::SUPERUSER`.

```php
use ReflectionMethod;
use Switon\Authorizing\VoterInterface;
use Switon\Core\Attribute\Autowired;
use Switon\Http\RequestInterface;

class IpAllowlistVoter implements VoterInterface
{
    #[Autowired] protected RequestInterface $request;

    public function vote(string $permission, ?ReflectionMethod $handler): ?bool
    {
        if (!str_starts_with($permission, 'admin::')) {
            return null;
        }

        if ($this->request->ip() !== '127.0.0.1') {
            return false;
        }

        return null;
    }
}
```

## Configuration {#configuration}

### Role-to-Permission Mapping {#role-mapping}

```yaml
# switon.yml
Switon\Authorizing\LookupInterface:
  permissions:
    admin: admin::create-user,admin::delete-user
    rbac-manager: rbac.role::index,rbac.role::edit
```

Use a custom `LookupInterface` implementation when permissions live in a database, cache, or external policy source.

### Voters {#voters-config}

```yaml
# switon.yml
Switon\Authorizing\AuthorizationInterface:
  voters:
    - App\Auth\IpAllowlistVoter
```

Voters are checked in order. `true` and `false` stop the chain; `null` lets the default checks continue.

## Keep in Mind {#keep-in-mind}

- `#[Authorize]` with no roles does not grant public access; use `Authorize::ANONYMOUS`.
- `Authorize::AUTHENTICATED` is a user-state marker, not a business role.
- Use `authorize()` when you want enforcement events; `can()` is only for branching.
- Default authorization flow is: voters, then identity-role `Authorize::SUPERUSER`, then handler attributes, then
  lookup.
- HTTP requests are authorized automatically through `Switon\Http\Event\RequestAuthorizing`; use `authorize()` directly
  only outside the controller flow.
- Keep lookup values exact; do not include spaces.

## Next {#next}

- **Authorization:** [Add authorization](../../../docs/en/guides/add-authorization.md#add-authorization)
- **Authentication:** [Add authentication](../../../docs/en/guides/add-authentication.md#add-authentication)
- **FAQ:** [FAQ](faq.md#authorization-faq)
- **Design:** [Design Rationale](design.md#design-rationale)
