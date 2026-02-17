<?php
namespace BoraSlim\Core\Modules;

use \BoraSlim\Core\Contracts\Modules\ModuleService;
use \BoraSlim\Core\Contracts\Modules\ModuleServiceInterface;
use \BoraSlim\Core\Support\Event;

abstract class ClientModule extends ModuleService implements ModuleServiceInterface{
    protected bool $booted = false;
    public bool $isCoreModule = false;
    protected bool $is_core = false;
    
    /**
     * Optional metadata for declarative registration.
     * Child classes can override this with:
     * [
     *   'name' => 'users',
     *   'type' => 'core',
     *   'enabled' => 1,
     * ]
     */
    protected ?array $moduleInfo = null;

    public function __construct()
    {
        //die('CoreModule here');
        $this->install();
        $this->boot();
    }

    public function install(): void {}
    public function boot(): void {}

    public function getJsPath(): ?string { return null; }
    public function getCssPath(): ?string { return null; }

    /**
     * Registers this core module in the database.
     * Uses $this->moduleInfo if defined, otherwise calls _registerInDB().
     */
    public function registerInDB(...$args) {
        // 🔹 Declarative auto-registration via moduleInfo property
        if (is_array($this->moduleInfo) && !empty($this->moduleInfo)) {
            return appDB()->insertIfNotExists('modules', $this->moduleInfo, 'name');
        }

        // 🔹 Fallback to method-based registration for advanced cases
        if (method_exists($this, '_registerInDB')) {
            return call_user_func_array([$this, '_registerInDB'], $args);
        }

        // 🔹 Optional developer feedback in debug mode
        if (defined('APP_DEBUG') && APP_DEBUG) {
            trigger_error(
                static::class . " has no moduleInfo or _registerInDB() method; skipping DB registration.",
                E_USER_NOTICE
            );
        }

        return false;
    }
}
