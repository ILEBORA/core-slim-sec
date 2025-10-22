<?php
/**
 * ================================================================
 *  BoraSlim Secure Distribution
 *  Framework:  ilebora/core-slim-sec
 *  Version:    2.1.1
 *  Build ID:   9BFCA31C1A56
 *  Timestamp:  2025-10-05 09:32:48
 *  License:    Proprietary - Unauthorized modification or redistribution prohibited.
 *  Contact:
 *  support@boracore.co.ke
 *  ileboratech@gmail.com
 *  +254 113 703 323
 * 
 *  Notice:
 *  This file is part of the BoraSlim Framework.
 *  Unauthorized modification or redistribution is prohibited.
 * 
 *  © 2025 ILEBORA Technologies. All Rights Reserved.
 * ================================================================
 */
use BoraSlim\Core\App;
use BoraSlim\Core\DB;
use BoraSlim\Core;

if (!function_exists('newSession')) {
    function newSession(array $settings = []) {
        if (session_status() === PHP_SESSION_NONE) {
            if (headers_sent()) {
                trigger_error("Cannot start session, headers already sent.", E_USER_WARNING);
                return;
            }

            // Environment-aware defaults
            $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
            $secure  = $settings['secure'] ?? ($isHttps ? 1 : 0);
            $samesite = $settings['samesite'] ?? ($secure ? 'None' : 'Lax');

            ini_set('session.cookie_secure', $secure);
            ini_set('session.cookie_samesite', $samesite);
            session_cache_limiter($settings['cache_limiter'] ?? 'private, must-revalidate');
            session_cache_expire($settings['cache_expire'] ?? 30);

            $name = $settings['name'] ?? (defined('ACS') ? ACS : 'borasession');
            session_name($name);

            session_start();
        }
    }
}

if (!function_exists('appDB')) {
    function appDB(): DB
    {
        return DB::getInstance();
    }
}

if (!function_exists('appDBC')) {
    function appDBC(): DB
    {
        $config = Config::load('config');
        $dbNameCnfg = ($config['db']['name'] ?? '') . '_cnfg';
        return DB::getInstance(null, null, null, $dbNameCnfg);
    }
}

if (!function_exists('getActiveRoutesFromDB')) {
    function getActiveRoutesFromDB() {
        $rows = appDB()->runQuery("SELECT `method`, `uri`, `controller`, `action` FROM `app_dynamic_routes` WHERE `enabled` = 1 ORDER BY `priority` DESC");
        return $rows->fetch_all(MYSQLI_ASSOC);
    }
}

if (!function_exists('processDBRoutesO')) {
    function processDBRoutesO($router){
        $routes = getActiveRoutesFromDB(); 
        // breakWith($routes);
        foreach ($routes as $route) {
            $class  = $route['controller'];
            $method = $route['action'];
            $uri    = $route['uri'];
            $http   = $route['method'];
            $permId = $route['permission_level_id'] ?? 1;
            $permKey= $route['permission_key'] ?? null;

            if (class_exists($class) && method_exists($class, $method)) {
                $permManager = myApp()->getFeature('permissions');
                // if (!$permManager->check($permId, $permKey)) {
                //     continue;
                // }

                $router->addRoute($route['method'], $route['uri'], "$class@$method");

                

                // $router->addRoute($http, $uri, function() use ($class, $method, $permId, $permKey) {
                //     // 🔒 Permission enforcement
                //     if (!Permission::check($permId, $permKey)) {
                //         header("HTTP/1.1 403 Forbidden");
                //         echo "Forbidden: You do not have access to this route.";
                //         exit;
                //     }

                //     // ✅ Call the real controller
                //     $controller = new $class();
                //     return call_user_func([$controller, $method]);
                // });
            }
        }

        return $router;
    }
}

if (!function_exists('processDBRoute')) {
    function processDBRoutes($router){
        $routes = getActiveRoutesFromDB(); 
        foreach ($routes as $route) {
            $class = $route['controller'];
            $method = $route['action'];
            
            if (class_exists($class) && method_exists($class, $method)) {
                // print("Class: $class Method: $method URI: {$route['uri']}<br>");
                $router->addRoute($route['method'], $route['uri'], "$class@$method");
            }
        }

        return $router;
    }
}

//TODO:: Cleanup
//Email
function isEmail($email) {
    return preg_match('|^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]{2,})+$|i', $email);
}
//General
function getIfSet(& $var,$default = null){
    if(isset($var)){
        return $var;
    }
    return $default;
}
function jsonExit($response){
    header("Content-Type:application/json");
    exit( $response );
}

function apiUsage(){
    return \BoraSlim\Core\Utils\ApiUsage::getInstance();
}

function apiRequest(){
    return new \BoraSlim\Core\Utils\ApiRequest;
}


function apiRequestError($message){
    return jsonExit(
        json_encode([
        'code' => 'X000',
        'message' => $message,
        'response' => 'bad',
        ])
    );
}
function getRequest($method = "POST"){
    $post = [];
    switch($method){
        case 'POST':
            $post = $_POST;
            break;
        case 'GET':
            $post = $_GET;
            break;
        case 'REQUEST':
            $post = $_REQUEST;
            break;
        default:
            $post = $_POST;
        break;
    }
    if(!count($post)){
        $postData = file_get_contents('php://input');
        $jdata = json_decode($postData,true);
        $post = $jdata;
    }

    return $post;
}


function getRequestValues($value, $item = "", $blank = false, $default = null){
    $value = is_string($value) ? trim($value) : $value;
    if(!$blank){
        $out = isset($value) 
                    ? (!empty($value)
                            ? $value
                            : die(apiRequestError("$item cannot be blank!"))) 
                    : die(apiRequestError("$item not set!"));
    }else{
        if($default){
            $out = $default;
        }else{
            $out = $value;
        }
    }

    return $out;
}

function preparePhone($phone,$int = true){
    if(substr($phone,0,1) == '0'){
        $phone = "254" . substr ($phone, 1);
    }
    return $phone;
}

function jsonResponse($status,$params){
    header("Content-Type:application/json");
    $response = new \ILEBORA\Response($status);
    // dieVal(__gl('siteConfig'));
    // $response->addMessage('systemCode', __gl('siteConfig')['sitemode']); 
    // dieVal($response->getResult());
    foreach($params as $key => $val){
        $response->addMessage($key, $val);    
    }

    return $response->getResult();
}

function getUserIpAddr(){
    if(!empty($_SERVER['HTTP_CLIENT_IP'])){
        //ip from share internet
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    }elseif(!empty($_SERVER['HTTP_X_FORWARDED_FOR'])){
        //ip pass from proxy
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    }else{
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    return $ip;
}


function userIP(){
    return getUserIpAddr();
}


function userID():string
{
    $userID = ''; //TODO:: get userID

    if (isset($_SESSION['access_token'])) {
        $payload = \App\Utils\Utils::validToken($_SESSION['access_token']);
        $user = $payload['user'];
        $userID = $user['id'];
    }
    
    return (string) $userID; 
}

function pass($vars){
    $obj = [];
    foreach($vars as $key => $val){
        $obj[$key] = $val;
    }
    return $obj;
}

//Templating
function addTemplate($params, $template = null,$module = null){
    
    
    if(!empty($params['image'])){
        $sectionTemplate = $template ?? "infosection_i";
    }else{
        $sectionTemplate = $template ?? "infosection";
    }
    
    $sectionTemplate .= '.php';
    
    $registeredVariables = pass($params);
    
    return includeSection($registeredVariables,$sectionTemplate,$module);
}

function includeSection($params, $template, $module = null){
    
    $filePath = str_replace("\\", DIRECTORY_SEPARATOR, $template);
    
    $modulePath = ($module) ? [str_replace("\\", DIRECTORY_SEPARATOR, BASE_DIR . "/private/src/Modules/".ucfirst($module)."/_shared/layouts/lyt")] : ['assets/views'];
   
    //$modulePath 'assets/views'
    $razr = new \Razr\Engine(new \Razr\Loader\FilesystemLoader($modulePath), '.cache');

    $registeredVariables = pass($params);
    
    return html_entity_decode($razr->render($filePath, $registeredVariables),ENT_QUOTES, 'UTF-8');
}


function filterInputs($allowed = [], $obj = []){
    //
    // dieVal($obj);
    $filtered = [];
    
    if(!empty($allowed)){
        //Get filtered array
        $allowed_keys = array_keys($allowed);
        $filtered = array_intersect_key($obj, array_flip($allowed_keys));
        
        //Run filter functions 
        foreach($filtered as $item => $value){
            $funct = $allowed[$item];
            if(!empty($funct)){
                $filtered[$item] = sanitizeItem($funct,$value);
            }
        }
        
        return $filtered;
    }
    
    return $filtered;
}

function sanitizeItem($funct, $value){
    $clean = trim($value);
    if(!is_array($funct)){
        switch($funct){
            case 'int':
                $clean = (int) filter_var($clean, FILTER_SANITIZE_NUMBER_INT);
            break;

            case 'decimal':
                $clean = (int) filter_var($clean, FILTER_SANITIZE_NUMBER_FLOAT,FILTER_FLAG_ALLOW_FRACTION);
            break;
            
            case 'date':
                $clean = (string) filter_var (preg_replace("([^0-9/] | [^0-9-])","",htmlentities($clean)));
            break;
            

            case 'message':
                $clean = strip_tags($clean);
                $clean = mysqli_real_escape_string(appDB()->mysqli,$clean);
            break;

            case 'file':
                $matcher = array('\\', '/', ':', '*', '?', '"', '<', '>', '|');
                $clean = str_replace($matcher, "_", $clean);
            break;

            case 'url':
                $clean = (string) filter_var($clean, FILTER_SANITIZE_URL);
            break;

            case 'escape_string':
                $clean = mysqli_real_escape_string(appDB()->mysqli,$clean);
            break;

            case 'ip':
                $clean = filter_var($clean, FILTER_VALIDATE_IP);
            break;

            case 'ipv4':
                $clean = filter_var($clean, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
            break;

            case 'ipv6':
                $clean = filter_var($clean, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
            break;


            case 'strip_special_blank':
                $matcher = array('\\', '/', ':', '*', '?', '"', '<', '>', '|');
                $clean = str_replace($matcher, "", $clean);
            break;

            case 'strip_special_underscore':
                $matcher = array('\\', '/', ':', '*', '?', '"', '<', '>', '|');
                $clean = str_replace($matcher, "_", $clean);
            break;

            case 'case_title':
                $clean = ucfirst($clean);
            break;

            case 'case_upper':
                $clean = strtoupper($clean);
            break;

            case 'case_lower':
                $clean = strtolower($clean);
            break;

        }
    }else{
        foreach($funct as $funct_i){
           $clean = sanitizeItem($funct_i,$clean);
        }
    }

    return $clean;
}

function App(): \BoraSlim\Core\Helpers\AppContainer
{
    static $instance;

    if (!$instance) {
        $instance = new \BoraSlim\Core\Helpers\AppContainer();
    }

    return $instance;
}

function Repo(): \BoraSlim\Core\Helpers\RepositoryResolver
{
    static $resolver;

    if (!$resolver) {
        $resolver = new \BoraSlim\Core\Helpers\RepositoryResolver();
    }

    return $resolver;
}

function Manage(): \BoraSlim\Core\Helpers\ManagerResolver
{
    static $resolver;

    if (!$resolver) {
        $resolver = new \BoraSlim\Core\Helpers\ManagerResolver();
    }

    return $resolver;
}

function Model(): \BoraSlim\Core\Helpers\ModelResolver
{
    static $resolver;

    if (!$resolver) {
        $resolver = new \BoraSlim\Core\Helpers\ModelResolver();
    }

    return $resolver;
}

if (!function_exists('ModManage')) {
    function ModManage() : \BoraSlim\Core\Managers\ModuleManager{
        return \BoraSlim\Core\App::getInstance()->getModules();
    }
}

if (!function_exists('Feature')) {
    function Feature(): \BoraSlim\Core\Helpers\FeatureResolver
    {
        return \BoraSlim\Core\App::getInstance()->getResolver();
    }
}

function Constants(){
    return new \BoraSlim\Core\Config\Constants;
}

//
function dieVal($val){
    if ($val) {
        if (is_array($val)) {
            die(print_r($val, true));
        }
        die(print_r($val, true));
    }
    die('null response');
}

// Alias function
function breakWith($val) {
    return dieVal($val);
}

//TODO:: Adopt view
use BoraSlim\Core\View;

if (!function_exists('View')) {
    function View(): View {
        static $instance = null;

        $app_name = App::config('app_name');
        $app_name = !empty($app_name) ? $app_name : 'BoraSlim App';
        $base_url = defined('BASE_URL') ? BASE_URL : '/';

        $rolePermissionManager = myApp()->getFeature('permissions'); //Manage()->permission->getInstance();
        // dieVal($rolePermissionManager);
        $rolePerms = $rolePermissionManager->getRoles(true);
        $currentRole = $rolePermissionManager->getCurrentRole();
        
        $encodedPerms = base64_encode(json_encode($rolePerms));
        $encodedRole = base64_encode(json_encode($currentRole));

        $menus = ModManage()->ui->manager->menu->getMenus();

        $app = ModManage()->ui->manager->buildUIContext();

        $prefs = ModManage()->ui->manager->user->getPrefs(true);
        
        if ($instance === null) {
            $instance = new View();
            $instance
                ->share('base_url', $base_url)
                ->share('app_name', $app_name)
                ->share('app_version', getVersion())
                ->share('core_version', getCoreVersion())
                ->share('access_permissions', $encodedPerms)
                ->share('access_role', $encodedRole)
                ->share('auth', [
                    'role' => $currentRole,
                    'permissions' => $rolePerms ,
                    'isGuest' => $currentRole === 'guest',
                ])
                ->share('meta_description', 'Learn more about our company and values.')
                ->share('meta_keywords', 'about, company, values')
                ->share('meta_author', 'MySite Team')
                ->share('meta_robots', 'index, follow')
                ->share('channelID', defined('CHANNEL_ID') ? CHANNEL_ID :'')
                ->share('redirectDefault', redirectDefault())

                //Extras
                ->share('app', $app)
                ->share('menus', $menus)
                ->share('prefs', $prefs)
                ;
        }

        return $instance;
    }
}

if(!function_exists('redirectDefault')){
    function redirectDefault(){
        $url = '';
        if( $role = myApp()->getFeature('permissions')->fetchCurrentRole()){
            switch($role){
                case 'Guest': $url = ''; break;
                case 'Client': $url = 'portal'; break;
                case 'Administrator':
                case 'Developer': $url = 'bo'; break;
                default: $url = ''; break;
            }
        }

        return $url;
    }
}

if (!function_exists('modView')) {
    function modView($module = null): View {
        static $instance = null;

        $app_name = App::config('app_name');
        $app_name = !empty($app_name) ? $app_name : 'BoraSlim App';
        $base_url = BASE_URL ?? '/';

        if ($instance === null) {
            $modulePath = ($module) ? 'modules/'.ucfirst($module).'/Views' : null;
            $instance = new View($modulePath);
            $instance
                ->share('base_url', $base_url)
                ->share('app_name', $app_name)
                ->share('app_version', getVersion())
                ->share('meta_description', 'Learn more about our company and values.')
                ->share('meta_keywords', 'about, company, values')
                ->share('meta_author', 'MySite Team')
                ->share('meta_robots', 'index, follow')
                ;
        }

        return $instance;
    }
}

if (!function_exists('getVersion')) {
     function getVersion(){
        $versionFile = '.config/.version';
        if(!file_exists($versionFile)){
            return $versionFile.' file not found.';
        }

        // Get the current version
        $currentVersion = trim(file_get_contents($versionFile));

        return $currentVersion;

    }
}

if (!function_exists('getCoreVersion')) {
     function getCoreVersion(){
        $versionFile = '.cache/.core.version';
        if(!file_exists($versionFile)){
            return '1.0.0';//$versionFile.' file not found.';
        }

        // Get the current version
        $currentVersion = trim(file_get_contents($versionFile));

        return $currentVersion;

    }
}

if (!function_exists('widgetCache')) {
    function widgetCache(string $key, callable $generator, int $ttl = 60): string
    {
        $cacheFile = sys_get_temp_dir() . "/widget_cache_$key.html";

        if (file_exists($cacheFile) && (filemtime($cacheFile) + $ttl > time())) {
            return file_get_contents($cacheFile);
        }

        $output = $generator();
        file_put_contents($cacheFile, $output);
        return $output;
    }
}


//** NEW */
if (!function_exists('hasPermission')) {
    /**
     * Check or register a permission.
     * 
     * @param string $module Module name (e.g. 'Users')
     * @param string $action Action name (e.g. 'deleteUsers')
     * @param bool $autoRegister Create permission if missing
     * @param bool $throw Throw exception if denied
     */
    // function hasPermissionO(string $module, string $action, bool $autoRegister = false, bool $throw = true): bool {
    //     $permRepo = ModManage()->permissions; // Assuming you have a PermissionsRepository
    //     $permission = $permRepo->findByName($module, $action);

    //     if (!$permission && $autoRegister) {
    //         $permRepo->create(['module' => $module, 'action' => $action]);
    //         return true;
    //     }

    //     $user = auth()->user(); // however you fetch the current user
    //     $has = $user && $user->hasPermission($module, $action);

    //     if (!$has && $throw) {
    //         throw new \Exception("Access denied: {$module}.{$action}");
    //     }

    //     return $has;
    // }

    function hasPermission(string $module, string $action, bool $autoRegister = false, bool $throw = false): bool {
        // $permRepo = ModManage()->permissions; // Assuming you have a PermissionsRepository
        // $permission = $permRepo->findByName($module, $action);

        // if (!$permission && $autoRegister) {
        //     $permRepo->create(['module' => $module, 'action' => $action]);
        //     return true;
        // }

        // $user = auth()->user(); // however you fetch the current user
        // $has = $user && $user->hasPermission($module, $action);

        // if (!$has && $throw) {
        //     throw new \Exception("Access denied: {$module}.{$action}");
        // }

        $has = $permManager->hasPermission($perm, $sub, $force_create);
        
        if (!$has && $throw) {
            throw new \Exception("Access denied: {$module}.{$action}");
        }

        return $has;
    }
}

// if (!function_exists('hasPermissionO')) {
//     function hasPermissionO($perm, $sub = null, $force_create = false){
//         // $class = Manage()->permission->getInstance();
//         // return $class->hasPermission($perm, $sub, $force_create);
//         $permManager = myApp()->getFeature('permissions');
//         // $class = Feature()->permissions->getInstance();  // note: key "permissions" must match registration
//         return $permManager->hasPermission($perm, $sub, $force_create);
//     }
// }


if (!function_exists('in_array_case_insensitive')) {
    function in_array_case_insensitive($needle, array $haystack): bool {
        return in_array(strtolower($needle), array_map('strtolower', $haystack));
    }
}

if (!function_exists('getMimeType')) {
    function getMimeType(string $path): string {
        $ext = pathinfo($path, PATHINFO_EXTENSION);

        $map = [
            'css'  => 'text/css',
            'js'   => 'application/javascript',
            'json' => 'application/json',
            'svg'  => 'image/svg+xml',
            'jpg'  => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'png'  => 'image/png',
            'gif'  => 'image/gif',
            'woff' => 'font/woff',
            'woff2'=> 'font/woff2',
            'ttf'  => 'font/ttf',
            'eot'  => 'application/vnd.ms-fontobject',
        ];

        return $map[$ext] ?? mime_content_type($path);
    }
}
if (!function_exists('extractVersion')) {
    function extractVersion(string $str): ?string {
        // Strip everything before the first digit
        $str = preg_replace('/^[^0-9]*/', '', $str);

        // Match version like 1.2.3, 1.2, 1.2.3-beta, 1.2.3+build, etc.
        if (preg_match('/^(\d+\.\d+(?:\.\d+)?(?:[-+][\w\.]+)?)/', $str, $matches)) {
            return $matches[1];
        }

        return null;
    }
}

if (!function_exists('isSameOrigin')) {
    function isSameOrigin(string $url): bool {
        $core = parse_url($url);
        $req = [
            'host' => $_SERVER['HTTP_HOST'] ?? '',
            'scheme' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http',
            'port' => $_SERVER['SERVER_PORT'] ?? null,
        ];

        return strcasecmp($core['host'], $req['host']) === 0
            && (!isset($core['scheme']) || strcasecmp($core['scheme'], $req['scheme']) === 0)
            && (!isset($core['port']) || $core['port'] == $req['port']);
    }
}

if(!function_exists('response')){
    function response(){
        return new \BoraSlim\Core\Utils\Response();
    }
}

if (!function_exists('myApp')) {
    function myApp(): \BoraSlim\Core\App
    {
        static $instance = null;
        if ($instance === null) {
            global $app;
            $instance = $app;
        }
        return $instance;
    }
}

if(!function_exists('isAjaxRequest')){
    function isAjaxRequest(): bool
    {
        return (
            !empty($_SERVER['HTTP_X_REQUESTED_WITH']) &&
            strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest'
        );
    }
}

if (!function_exists('appConstants')) {
    /**
     * Usage: 
     *   appConstants('ROLE_ADMIN')  → returns the value
     *   appConstants()::ROLE_ADMIN  → returns via class reference
     */ 
    function appConstants(?string $key = null)
    {
        $class = class_exists(\App\Config\Constants::class)
            ? \App\Config\Constants::class
            : \BoraSlim\Core\Config\Constants::class;

        // If no key is provided, return the class itself
        if ($key === null) {
            return $class;
        }

        // Otherwise, resolve the constant value
        if (defined("{$class}::{$key}")) {
            return constant("{$class}::{$key}");
        }

        throw new \Exception("Constant {$key} not defined in {$class}");
    }
}


if(!function_exists('Redirect')){
    function Redirect() : \App\Utils\Redirect{
        return new \App\Utils\Redirect();
    }
}

if(!function_exists('CryptoJSAesEncrypt')){
    function CryptoJSAesEncrypt($plain_text, $passphrase = "" ){
        $salt = openssl_random_pseudo_bytes(256);
        $iv = openssl_random_pseudo_bytes(16);
        $iterations = 999; 
        $passphrase = getIfSet($_SESSION['APP_KEY'],''); 
        $key = hash_pbkdf2("sha512", $passphrase, $salt, $iterations, 64);

        $encrypted_data = openssl_encrypt($plain_text, 'aes-256-cbc', hex2bin($key), OPENSSL_RAW_DATA, $iv);

        $data = array("ciphertext" => base64_encode($encrypted_data), "iv" => bin2hex($iv), "salt" => bin2hex($salt));
        return json_encode($data);
    }
}


if(!function_exists('Hooks')){
    function Hooks(){
        return \App\Utils\Hooks::getInstance();
    }
}

if(!file_exists('sanitizeFolderName')){
    function sanitizeFolderName($name) {
        // Replace colons and other non-alphanumeric characters (except underscores and dashes) with an underscore
        $sanitized = preg_replace('/[^a-zA-Z0-9_-]/', '_', $name);
        
        // Optional: collapse multiple underscores
        $sanitized = preg_replace('/_+/', '_', $sanitized);

        // Trim underscores from start and end
        return trim($sanitized, '_');
    }
}

if(!function_exists('handleCoreDownload')){
    function handleCoreDownload(string $clientId): string|false
    {
        $corePath = ".core/core.bora";
        $systemKey = $_ENV['SYSTEM_KEY'];
        $systemIv = $_ENV['SYSTEM_IV'];

        if (!$clientId) {
            return false;
        }

        // Simulate client-specific key (you could fetch this from DB)
        $clientSecret = $_ENV['CORE_CLIENT_SECRET'];
        $clientIv = hex2bin($_ENV['CORE_CLIENT_IV']);

        if (!file_exists($corePath)) {
            return false;
        }

        // Decrypt system-layer core
        $encCore = file_get_contents($corePath);
        $layer1 = openssl_decrypt($encCore, 'AES-256-CTR', $systemKey, 0, $systemIv);

        if ($layer1 === false) {
            return false;
        }
        
        // Re-encrypt for client
        $clientEnc = openssl_encrypt($layer1, 'AES-256-CTR', $clientSecret, 0, $clientIv);

        return $clientEnc ?: false;
    }
}

if (!function_exists('Event')) {
    function Event(): \BoraSlim\Core\Support\Event {
        static $event = null;
        if ($event === null) {
            $event = new \BoraSlim\Core\Support\Event();
        }
        return $event;
    }
}

if (!function_exists('Logger')) {
    function Logger(): \BoraSlim\Core\Support\Logger {
        static $logger = null;
        if ($logger === null) {
            $logger = new \BoraSlim\Core\Support\Logger();
        }
        return $logger;
    }
}


if (!function_exists('sql')) {
    function sql(){
        return new \BoraSlim\Core\Support\SqlQueryBuilder();
    }
}

if (!function_exists('Grid')) {
    function Grid(string $type = 'table') {
        return ModManage()->grids->$type;
    }
}