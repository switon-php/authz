<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Unit;

use Switon\Authorizing\Attribute\Authorize;
use Switon\Authorizing\Permissions;
use Switon\Authorizing\Tests\Fixtures\PermissionScanner\AdminController;
use Switon\Authorizing\Tests\Fixtures\PermissionScanner\CustomRoleController;
use Switon\Authorizing\Tests\Fixtures\PermissionScanner\DelegatedController;
use Switon\Authorizing\Tests\Fixtures\PermissionScanner\GuestController;
use Switon\Authorizing\Tests\Fixtures\PermissionScanner\MultiRoleController;
use Switon\Authorizing\Tests\Fixtures\PermissionScanner\PublicController;
use Switon\Authorizing\Tests\Fixtures\PermissionScanner\ReferencedController;
use Switon\Routing\ControllerScannerInterface;
use Switon\Routing\HandlerIdInterface;
use Switon\Authorizing\Tests\TestCase;
use RuntimeException;

class PermissionScannerTest extends TestCase
{
    public function testScanReturnsGroupedActionsAndSparsePermissionsFromAuthorizeMetadata(): void
    {
        $controllerScanner = new class () implements ControllerScannerInterface {
            public function getControllers(): array
            {
                return [
                    AdminController::class,
                    PublicController::class,
                    GuestController::class,
                    CustomRoleController::class,
                    DelegatedController::class,
                    MultiRoleController::class,
                    ReferencedController::class,
                ];
            }
        };

        $handlerId = new class () implements HandlerIdInterface {
            public function getId(string $controller, string $action): string
            {
                return match ([$controller, $action]) {
                    [AdminController::class, '*'] => 'admin::*',
                    [AdminController::class, 'dashboardAction'] => 'admin::dashboard',
                    [AdminController::class, 'createUserAction'] => 'admin::create-user',
                    [PublicController::class, 'infoAction'] => 'public::info',
                    [PublicController::class, 'profileAction'] => 'public::profile',
                    [GuestController::class, '*'] => 'guest::*',
                    [GuestController::class, 'indexAction'] => 'guest::index',
                    [CustomRoleController::class, 'editAction'] => 'custom::edit',
                    [DelegatedController::class, '*'] => 'delegated::*',
                    [DelegatedController::class, 'indexAction'] => 'delegated::index',
                    [DelegatedController::class, 'editAction'] => 'delegated::edit',
                    [MultiRoleController::class, '*'] => 'multi::*',
                    [MultiRoleController::class, 'indexAction'] => 'multi::index',
                    [MultiRoleController::class, 'settingsAction'] => 'multi::settings',
                    [ReferencedController::class, '*'] => 'referenced::*',
                    [ReferencedController::class, 'indexAction'] => 'referenced::index',
                    [ReferencedController::class, 'deleteAction'] => 'referenced::delete',
                    default => throw new RuntimeException('Unexpected handler lookup'),
                };
            }
        };

        /** @var Permissions $permissions */
        $permissions = $this->make(Permissions::class, [
            'controllerScanner' => $controllerScanner,
            'handlerId' => $handlerId,
        ]);

        $result = $permissions->scanCatalog();

        $this->assertSame([
            'admin' => [
                'class' => AdminController::class,
                'actions' => [
                    'create-user' => 'createUserAction',
                    'dashboard' => 'dashboardAction',
                ],
                'permissions' => [
                    '*' => [
                        'method' => '*',
                        'roles' => [Authorize::SUPERUSER],
                        'reference' => null,
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                ],
            ],
            'custom' => [
                'class' => CustomRoleController::class,
                'actions' => [
                    'edit' => 'editAction',
                ],
                'permissions' => [
                    'edit' => [
                        'method' => 'editAction',
                        'roles' => ['editor'],
                        'reference' => null,
                        'assignable' => false,
                        'assignable_explicit' => true,
                    ],
                ],
            ],
            'delegated' => [
                'class' => DelegatedController::class,
                'actions' => [
                    'edit' => 'editAction',
                    'index' => 'indexAction',
                ],
                'permissions' => [
                    '*' => [
                        'method' => '*',
                        'roles' => [],
                        'reference' => null,
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                    'edit' => [
                        'method' => 'editAction',
                        'roles' => ['editor'],
                        'reference' => null,
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                ],
            ],
            'guest' => [
                'class' => GuestController::class,
                'actions' => [
                    'index' => 'indexAction',
                ],
                'permissions' => [
                    '*' => [
                        'method' => '*',
                        'roles' => [Authorize::ANONYMOUS],
                        'reference' => null,
                        'assignable' => false,
                        'assignable_explicit' => false,
                    ],
                ],
            ],
            'multi' => [
                'class' => MultiRoleController::class,
                'actions' => [
                    'index' => 'indexAction',
                    'settings' => 'settingsAction',
                ],
                'permissions' => [
                    '*' => [
                        'method' => '*',
                        'roles' => [Authorize::AUTHENTICATED],
                        'reference' => null,
                        'assignable' => false,
                        'assignable_explicit' => false,
                    ],
                ],
            ],
            'public' => [
                'class' => PublicController::class,
                'actions' => [
                    'info' => 'infoAction',
                    'profile' => 'profileAction',
                ],
                'permissions' => [
                    'info' => [
                        'method' => 'infoAction',
                        'roles' => [],
                        'reference' => null,
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                    'profile' => [
                        'method' => 'profileAction',
                        'roles' => [Authorize::AUTHENTICATED],
                        'reference' => null,
                        'assignable' => false,
                        'assignable_explicit' => true,
                    ],
                ],
            ],
            'referenced' => [
                'class' => ReferencedController::class,
                'actions' => [
                    'delete' => 'deleteAction',
                    'index' => 'indexAction',
                ],
                'permissions' => [
                    '*' => [
                        'method' => '*',
                        'roles' => [Authorize::AUTHENTICATED],
                        'reference' => null,
                        'assignable' => false,
                        'assignable_explicit' => false,
                    ],
                    'delete' => [
                        'method' => 'deleteAction',
                        'roles' => [Authorize::AUTHENTICATED],
                        'reference' => 'index',
                        'assignable' => false,
                        'assignable_explicit' => false,
                    ],
                ],
            ],
        ], $result);

        $this->assertArrayNotHasKey('dashboard', $result['admin']['permissions']);
        $this->assertArrayNotHasKey('create-user', $result['admin']['permissions']);
        $this->assertArrayNotHasKey('index', $result['delegated']['permissions']);
    }
}
