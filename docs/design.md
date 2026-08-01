# Design Rationale {#design-rationale}

`switon/authz` keeps access rules close to HTTP handlers, keeps identity-state markers separate from business roles, and keeps runtime checks on exact permission codes.

## See also {#see-also}

- [Authorization Package](README.md) — usage, configuration, and pitfalls
- [FAQ](faq.md#authorization-faq) — common questions and troubleshooting

---

## Controller First {#controller-first}

Most access rules are easier to review when they live on the controller or method that owns the behavior.

- **Class default:** `#[Authorize]` on the controller sets the baseline rule.
- **Method override:** a method-level attribute replaces the class default for that method only.

## User States And Roles {#user-states-and-roles}

- **Identity state:** `Authorize::ANONYMOUS` and `Authorize::AUTHENTICATED` mark anonymous vs authenticated handling.
- **Bypass role:** `Authorize::SUPERUSER` is the built-in global bypass key.
- **Application roles:** custom role strings belong to the application; `LookupInterface` maps them to permission codes.

This split keeps public and authenticated flow separate from application permissions.

## One Runtime Path {#one-runtime-path}

`AuthorizationInterface` uses one API for controller gates and service checks.

- **Permission codes:** plain strings stay on the permission path.
- **Handler references:** a real `FQCN::method` string is treated as a handler reference.
- **can():** returns a boolean for branching.
- **authorize():** raises HTTP exceptions and emits `AuthorizationGranted` / `AuthorizationDenied`.

That keeps the runtime contract small while still supporting controller metadata when needed.

## Role-to-Permission Mapping {#permission-lookup}

- **Format:** `LookupInterface` uses comma-separated permission codes for fast exact matching.
- **Trade-off:** lookup sources must normalize values carefully, including values that come from database rows or config strings.

## Catalogs Stay Separate From Enforcement {#catalogs-stay-separate-from-enforcement}

- **Catalogs and RBAC UIs:** use `PermissionsInterface` for scans, exports, and administration screens.
- **Enforcement events:** `AuthorizationGranted` and `AuthorizationDenied` accompany `authorize()`.

Keeping those paths separate avoids turning runtime checks into a merged policy dump.
