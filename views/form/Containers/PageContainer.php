<?php
namespace BoraSlim\Core\Modules\Form\Views\Containers;

class PageContainer{
    private static $container = 'page';
    private static $anime = 'fadeIn';

    public static function render($content, $folder, $type){
        return '<div class="form-container form-'.self::$container.' '.$folder.'_'.$type.'_form animated '.self::$anime.' ">' . $content . '</div>';
    }
}