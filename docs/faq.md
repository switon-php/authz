# Authorization FAQ {#authorization-faq}
Short answers for common access checks.

## Getting Started {#getting-started}

### How do I allow guest access? {#guest-access}

Use `#[Authorize(Authorize::ANONYMOUS)]`.

### What does empty `#[Authorize]` do? {#empty-authorize}

It does not grant public access. Use `Authorize::ANONYMOUS` when the method should be public. Empty `#[Authorize]` still keeps the method in the authorization flow. For authenticated users, the empty attribute continues to permission
lookup. For guests, access is denied before lookup.

### What does `#[Authorize('@edit')]` do? {#authorize-reference}

It records a permission reference for scanning and catalogs. Runtime access checks still use the resolved handler permission path and normal lookup rules.

### Should I use `can()` or `authorize()`? {#can-vs-authorize}

Use `can()` for branches and `authorize()` for HTTP boundaries.

### Where do roles come from? {#roles-source}

From `Switon\Principal\IdentityInterface::getRoles()`. Authentication stays in the identity layer.

## Configuration {#configuration}

### How do custom roles get permissions? {#custom-role-permissions}

Map them in `LookupInterface` as exact comma-separated codes.

### How do I register voters? {#register-voters}

Configure `Switon\Authorizing\AuthorizationInterface` with a `voters` list in `switon.yml`.

### How do I build a catalog or RBAC UI? {#catalog-ui}

Use `PermissionsInterface`.

## Troubleshooting {#troubleshooting}

### Why is a custom role denied? {#custom-role-denied}

Check exact permission code spelling. In `LookupInterface` mapping, use comma-separated codes **without spaces**.

### Why is a handler reference denied? {#handler-reference-denied}

Only a real `FQCN::method` with both `\` and `::` is treated as a handler reference. If the method does not exist, authz
denies immediately. Plain strings such as `admin::index` stay on the permission path.

### How do I choose between `401` and `403`? {#401-vs-403}

An empty resolved role set produces `UnauthorizedException`; a non-empty resolved role set produces
`ForbiddenException`.

### Can a voter block `Authorize::SUPERUSER`? {#voter-block-superuser}

Yes. Voters run before the built-in role grant path, so a `false` vote can deny access even when the identity contains
`Authorize::SUPERUSER`.

### When is a handler reference recognized? {#handler-reference-rules}

Only a real `FQCN::method` with both `\` and `::`, plus an existing method, is treated as a handler reference.
Anything else stays on the permission path.

### When do `AuthorizationGranted` and `AuthorizationDenied` fire? {#authz-events}

Only from `authorize()`.
