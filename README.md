# Switon Authz Package

[![CI](https://img.shields.io/github/actions/workflow/status/switon-php/authz/ci.yml?branch=main&label=CI)](https://github.com/switon-php/authz/actions/workflows/ci.yml) [![PHP 8.3+](https://img.shields.io/badge/PHP-8.3%2B-777BB4)](https://www.php.net/)

Switon's HTTP authorization layer for controller and action policies, identity states, and voter-based access control.

## Highlights

- **Attribute-based access rules:** `#[Authorize]` lets controllers and actions declare policy in place.
- **Layered defaults:** class-level rules set the baseline, and method rules can override them.
- **Policy aliases:** `@edit`-style references stay tied to their targets.
- **Decision hooks:** `VoterInterface` can grant, deny, or abstain before the default check runs.
- **Identity states:** authenticated, anonymous, and superuser access are handled explicitly.

## Installation

```bash
composer require switon/authz
```

## Quick Start

```php
use Switon\Authorizing\Attribute\Authorize;

#[Authorize(Authorize::AUTHENTICATED)]
class UserController
{
    public function indexAction(): void
    {
    }

    public function profileAction(): void
    {
    }

    #[Authorize(Authorize::ANONYMOUS)]
    public function publicAction(): void
    {
    }

    #[Authorize('@index')]
    public function deleteAction(): void
    {
    }
}
```

Docs: https://docs.switon.dev/latest/authz

## License

MIT.
