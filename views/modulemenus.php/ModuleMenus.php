<?php
namespace BoraSlim\Core\Modules;

class ModuleMenus
{
    protected static $menus = [];

    public static function add($module, array $menuItems)
    {
        self::$menus[strtolower($module)] = $menuItems;
    }

    public static function get($module)
    {
        $key = strtolower($module);
        return self::$menus[$key] ?? [];
    }
}