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

use BoraSlim\Core\Support\Session;

if (!function_exists('Session')) {
    function Session(): string
    {
        return Session::class;
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
        // dieVal($routes);
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
    exit( is_array($response) ? json_encode($response) : $response );
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
        case 'FILES':
            $post = $_FILES;
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

function getRequestN() {
    $method = $_SERVER['REQUEST_METHOD'];
    $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
    
    // Handle simple cases
    if ($method === 'GET')    return $_GET;
    if ($method === 'POST' && strpos($contentType, 'multipart/form-data') !== false) {
        return array_merge($_POST, $_FILES); // files + text fields
    }
    if ($method === 'POST')   return $_POST;
    
    // Handle API verbs (PUT / PATCH / DELETE)
    if (in_array($method, ['PUT','PATCH','DELETE'])) {
        parse_str(file_get_contents('php://input'), $data);
        return $data ?: [];
    }

    // Handle JSON bodies
    if (strpos($contentType, 'application/json') !== false) {
        return json_decode(file_get_contents('php://input'), true) ?? [];
    }

    // Fallback
    return $_REQUEST;
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
    $response = new \BoraSlim\Core\Utils\ResponseMessage($status);
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
    $userID = $_SESSION['id']??''; //TODO:: get userID

    if (isset($_SESSION['access_token'])) {
        $payload = \BoraSlim\Core\Modules\App\Utils\Utils::validToken($_SESSION['access_token']);
        $user = $payload['user'];
        $userID = $user['id'];
    }
    
    return (string) $userID; 
}

function sessionID(){
    return getIfSet($_SESSION['client'],'1234');
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
    return ModManage()?->ui?->manager?->template->addTemplate($params, $template,$module)??'Template not found!';
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
    // Shared static variable outside both functions
    static $clientCallbacks = [];

    /**
     * Returns the singleton View instance.
     * Allows vendor defaults plus client extensions.
     */
    function View(): View {
        static $instance = null;
        global $clientCallbacks; // 👈 ensure same variable

        if ($instance === null) {
            $instance = new View();

            // --- Vendor Defaults ---
            $baseUrl = defined('BASE_URL') ? BASE_URL : '/';
            $appConfig = App::appConfig();
            $appName = App::config('app_name') ?: 'BoraSlim App';

            $instance
                ->share('current_user_id', userID())
                ->share('base_url', $baseUrl)
                ->share('app_name', $appName)
                ->share('app_version', getVersion())
                ->share('core_version', getCoreVersion());

            foreach($appConfig as $key => $val){
                $instance
                ->share($key, $val);
            }

            // --- Execute registered client callbacks ---
            foreach ($clientCallbacks??[] as $callback) {
                if (is_callable($callback)) {
                    $callback($instance);
                }
            }
        }

        return $instance;
    }

    /**
     * Registers a client callback to extend View shares.
     * Can be called multiple times by different modules.
     */
    function registerViewShares(callable $callback): void {
        global $clientCallbacks; // 👈 same variable
        $clientCallbacks[] = $callback;
    }
} 

if (!function_exists('viewVar')) {
    function viewVar(string $key, $default = null)
    {
        $view = View();
        if (!$view) return $default;
        return $view->get($key, $default);
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

    function hasPermission(string $module, string $action, bool $autoRegister = false, bool $throw = false): bool {
        $permManager = myApp()->getFeature('permissions');
        $module = strtolower($module);
        $action = strtolower($action);
        
        $has = $permManager->hasPermission($module, $action, $autoRegister);
        
        if (!$has && $throw) {
            // throw new \Exception("Access denied: {$module}.{$action}");
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
        return \BoraSlim\Core\App::getInstance();
        // static $instance = null;
        // if ($instance === null) {
        //     global $app;
        //     $instance = $app;
        // }
        // return $instance;
    }
}

if (!function_exists('appVar')) {
    function appVar(?string $key = null, $default = null)
    {
        $shared = View()->getShared();
        return $shared[$key] ?? $default;
    }
}

if (!function_exists('meta')) {
    function meta(string $key, $default = '') {
        $shared = View()->getShared();
        return $shared['meta_'.$key]
            ?? ($shared['seo'][$key] ?? $default);
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
        $class = class_exists(\BoraSlim\Core\Modules\App\Config\Constants::class)
            ? \BoraSlim\Core\Modules\App\Config\Constants::class
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
    function Redirect() : \BoraSlim\Core\Modules\App\Utils\Redirect{
        return new \BoraSlim\Core\Modules\App\Utils\Redirect();
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
    function Hooks($name = 'global'){
        // return \BoraSlim\Core\Modules\App\Utils\Hooks::getInstance();
    return myApp()
        ->getService('hooks')
        ->channel($name);
    }
}

if(!function_exists('HooksLegacy')){
    function HooksLegacy()
    {
        static $adapter;

        if(!$adapter){
            $adapter = new \BoraSlim\Core\Hooks\LegacyHooksAdapter();
        }

        return $adapter;
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

if (!function_exists('safeSelect')) {
    function safeSelect($table, $exclude = []) {
        $db = appDB();
        $colsData = $db->query("SHOW COLUMNS FROM {$table}")->fetch_all(MYSQLI_ASSOC);

        // Extract just the column names
        $cols = array_column($colsData, 'Field');

        // Remove excluded fields
        $cols = array_diff($cols, $exclude);

        // Return a comma-separated list
        return implode(',', $cols);
    }
}

if (!function_exists('vendor_path')){
    function vendor_path($relative) {
        return __DIR__ . "/{$relative}";
    }
}

if (!function_exists('public_path')) {
    function public_path($relative = '') {
        return 'assets' . ($relative ? '/' . ltrim($relative, '/') : '');
    }
}


if(!function_exists('autoIncludeCoreJs')){
    function autoIncludeCoreJs($hooks)
    {
        $corePath = vendor_path('public/js/core');
        $manifest = include $corePath . '/manifest.php';

        $currentEnv = $_ENV['ENV_DEVELOPMENT'] ? 'dev' : 'prod';
        $tenant     = $_ENV['PRJCTN'] ?? '*';

        $preload = []; // ✅ IMPORTANT

        // Filter
        $manifest = array_filter($manifest, function ($meta) use ($currentEnv, $tenant) {

            $envAllowed = in_array('*', $meta['env'] ?? ['*'])
                    || in_array($currentEnv, $meta['env'] ?? []);

            $tenantAllowed = in_array('*', $meta['tenants'] ?? ['*'])
                        || in_array($tenant, $meta['tenants'] ?? []);

            return $envAllowed && $tenantAllowed;
        });

        // Sort by priority
        uasort($manifest, function ($a, $b) {
            return ($a['priority'] ?? 100)
                <=> ($b['priority'] ?? 100);
        });

        foreach ($manifest as $name => $meta) {

            $file = $meta['file'] ?? null;

            /* Inline asset */
            if ($file === '__inline__') {
                $hooks->registerInline($name, '');
            } else {

                $filePath = $corePath . '/' . $meta['file'];

                if (!file_exists($filePath)){
                    error_log("Error Registering file:: $name :: $filePath");
                    continue;
                }

                // $manifest[$name]['file'] = 'vendor/ilebora/core-slim-sec/public/js/core/'. $file ;
                if(isset($manifest[$name]['bypass'])){
                    $manifest[$name]['file'] = 'vendor/ilebora/core-slim-sec/public/js/core/'. $file ;
                }else{
                    $compiled = \BoraSlim\Core\Assets\JsAssetCompiler::compile($name, $filePath);
                    $manifest[$name]['file'] = $compiled['url'];
                }
                
                // dieVal($compiled);
                $hooks->register($name, $filePath);
            }

            // ✅ preload collection (works for both inline + file)
            if (!empty($meta['preload'])) {
                $preload[] = $name;
            }
        }

        $GLOBALS['__BORA_CORE_MANIFEST__'] = $manifest;
        $GLOBALS['__BORA_PRELOAD__'] = $preload;
    }
}

function buildCoreManifest(): array
{
    $corePath = vendor_path('public/js/core');
    $manifest = include $corePath . '/manifest.php';

    $currentEnv = $_ENV['ENV_DEVELOPMENT'] ? 'dev' : 'prod';
    $tenant     = $_ENV['PRJCTN'] ?? '*';

    // Filter
    $manifest = array_filter($manifest, function ($meta) use ($currentEnv, $tenant) {

        $envAllowed = in_array('*', $meta['env'] ?? ['*'])
            || in_array($currentEnv, $meta['env'] ?? []);

        $tenantAllowed = in_array('*', $meta['tenants'] ?? ['*'])
            || in_array($tenant, $meta['tenants'] ?? []);

        return $envAllowed && $tenantAllowed;
    });

    // Sort
    uasort($manifest, function ($a, $b) {
        return ($a['priority'] ?? 100) <=> ($b['priority'] ?? 100);
    });

    return $manifest;
}

function prepareCoreManifest(array $manifest): array
{
    $corePath = vendor_path('public/js/core');

    foreach ($manifest as $name => &$meta) {

        $file = $meta['file'] ?? null;

        if ($file && $file !== '__inline__') {

            $filePath = $corePath . '/' . $file;

            if (!file_exists($filePath)) {
                error_log("Error Registering file:: $name :: $filePath");
                continue;
            }

            if (isset($meta['bypass'])) {
                $meta['file'] = 'vendor/ilebora/core-slim-sec/public/js/core/' . $file;
            } else {
                $compiled = \BoraSlim\Core\Assets\JsAssetCompiler::compile($name, $filePath);
                $meta['file'] = $compiled['url'];
            }
        }
    }

    return $manifest;
}

function registerCoreScripts($hooks, array $manifest): array
{
    $corePath = vendor_path('public/js/core');
    $preload = [];

    foreach ($manifest as $name => $meta) {

        $file = $meta['file'] ?? null;

        if ($file === '__inline__') {
            $hooks->registerInline($name, '');
        } else {

            $filePath = $corePath . '/' . ($meta['original'] ?? basename($meta['file']));
            
            $hooks->register($name, $filePath);
        }

        if (!empty($meta['preload'])) {
            $preload[] = $name;
        }
    }

    return $preload;
}

if(!function_exists('autoIncludeCoreCss')){
    function autoIncludeCoreCss($hooks) {
        $corePath = vendor_path('public/css/cores');

        $files = glob($corePath . '/*.css');
        // dieVal($files);
        foreach ($files as $file) {
            $name = basename($file, '.css'); // e.g., BoraHooks
            $hooks->register(strtolower($name), $file);
        }
    }
}

if(!function_exists('Status')){
    function Status(){
        return new \BoraSlim\Core\Utils\Status;
    }
}

use BoraSlim\Core\Database\DBMigrate as DBMigrateClass;
if (!function_exists('DBMigrate')) {
    function DBMigrate(): string
    {
        // Return the fully qualified class name for static access
        return DBMigrateClass::class;
    }
}

if (!function_exists('csrf_token')) {
    function csrf_token() {
        if (session_status() === PHP_SESSION_NONE) {
            // session_start();
        }

        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }

        return $_SESSION['csrf_token'];
    }
}

use BoraSlim\Core\Helpers\RedisCache;

if (!function_exists('RedisCache')) {
    function RedisCache() {
        return RedisCache::class;
    }
}

if (!function_exists('env')) {
    function env($key, $default = null) {
        return getenv($key) ?: ($_ENV[$key] ?? $default);
    }
}

use BoraSlim\Core\Helpers\WithResolver;
if (!function_exists('With')) {
    function With($name) {
        return WithResolver::get($name);
    }
}

if(!function_exists('appMode')){
    function appMode($check = null) {
        $mode = defined('APP_MODE') ? APP_MODE : 'live';
        return $check ? $mode === $check : $mode;
    }
}

if(!function_exists('hideData')){
    function hideData($address){
        $e="";
        for ($n = 0; $n < strlen($address); $n++) {       
            $c = htmlentities($address[$n],ENT_QUOTES,'UTF-8');
            $address[$n] == $c ? $e .= "&#".ord($address[$n]).";" : $e .= $c;
        }       
        return($e);
    }
}

if(!function_exists('make_thumb')){
    function make_thumb($img_name,$filename,$new_w,$new_h=0){
        $src_img=imagecreatefromjpeg($img_name);
        $old_x=imageSX($src_img);
        $old_y=imageSY($src_img);
    
        $ratio1=$old_x/$new_w;
        $ratio2=$old_y/$new_h;
        if($ratio1>$ratio2)	{
        $thumb_w=$new_w;
        $thumb_h=$old_y/$ratio1;
        }
        else	{
        $thumb_h=$new_h;
        $thumb_w=$old_x/$ratio2;
        }
    
        $dst_img=imagecreatetruecolor($thumb_w,$thumb_h);
        imagecopyresampled($dst_img,$src_img,0,0,0,0,$thumb_w,$thumb_h,$old_x,$old_y); 
        imagejpeg($dst_img,$filename); 
        imagedestroy($dst_img); 
        imagedestroy($src_img); 
    }
}

if(!function_exists('cropImage')){
    function cropImage($sourcePath, $thumbSize, $destination = null) {
        $parts = explode('.', $sourcePath);
        $ext = $parts[count($parts) - 1];
        if ($ext == 'jpg' || $ext == 'jpeg') {
        $format = 'jpg';
        } else {
        $format = 'png';
        }
    
        if ($format == 'jpg') {
        $sourceImage = imagecreatefromjpeg($sourcePath);
        }
        if ($format == 'png') {
        $sourceImage = imagecreatefrompng($sourcePath);
        }
    
        list($srcWidth, $srcHeight) = getimagesize($sourcePath);
    
        // calculating the part of the image to use for thumbnail
        if ($srcWidth > $srcHeight) {
        $y = 0;
        $x = ($srcWidth - $srcHeight) / 2;
        $smallestSide = $srcHeight;
        } else {
        $x = 0;
        $y = ($srcHeight - $srcWidth) / 2;
        $smallestSide = $srcWidth;
        }
    
        $destinationImage = imagecreatetruecolor($thumbSize, $thumbSize);
        imagecopyresampled($destinationImage, $sourceImage, 0, 0, $x, $y, $thumbSize, $thumbSize, $smallestSide, $smallestSide);
    
        if ($destination == null) {
        header('Content-Type: image/jpeg');
        if ($format == 'jpg') {
            imagejpeg($destinationImage, null, 100);
        }
        if ($format == 'png') {
            imagejpeg($destinationImage);
        }
        if ($destination = null) {
        }
        } else {
        if ($format == 'jpg') {
            imagejpeg($destinationImage, $destination, 100);
        }
        if ($format == 'png') {
            imagepng($destinationImage, $destination);
        }
        }
    }
}

if(!function_exists('createAvatarImage')){
    function createAvatarImage($string){
        
        $imageFilePath = "assets/uploads/avatar/".$string . ".png";

        if(!file_exists($imageFilePath)){
        //base avatar image that we use to center our text string on top of it.
        $avatar = imagecreatetruecolor(60,60);

        $bg_color = imagecolorallocate($avatar, 242, 242, 242);

        imagefill($avatar,0,0,$bg_color);

        $avatar_text_color = imagecolorallocate($avatar, 255, 255, 255);

        // Load the gd font and write 
        $font = imageloadfont('assets/fonts/gd/gd-font.gdf');

        imagestring($avatar, $font, 10, 10, strtoupper($string), $avatar_text_color);

        imagepng($avatar, $imageFilePath);

        imagedestroy($avatar);
        }

        return $imageFilePath;
    }
}

if(!function_exists('secureFile')){
    function secureFile($file){
        return 'viewer?byp=1&j='.$file.'&tm='.time();
    }
}

if(!function_exists('getTextAvatar')){
    function getTextAvatar($name){
        $nameFirstChar = ucfirst($name[0]);
        $avatar = 'assets/uploads/avatar/'.$nameFirstChar.'.png';
        if(!file_exists($avatar)){
            createAvatarImage($nameFirstChar);
        }
        return $avatar;
    }
}

if (!function_exists('systemConfig')) {

    /**
     * Load a configuration file from /config.
     * 
     * Usage:
     *   systemConfig('notifiable_items');
     *   systemConfig('app.name');
     *   systemConfig('database.connections.mysql');
     */
    function systemConfig(?string $key = null, $default = null)
    {
        static $cache = [];

        if ($key === null) {
            return null;
        }

        // Split "notifiable_items" → ['notifiable_items']
        // or "app.name" → ['app', 'name']
        $segments = explode('.', $key);
        $file = array_shift($segments); // first part is filename

        // Cache key for entire file
        if (!isset($cache[$file])) {

            $path = BASE_DIR . "/.config/{$file}.php";

            if (!file_exists($path)) {
                return $default;
            }

            // Load and cache the file
            $cache[$file] = include $path;
        }

        // Navigate deeper: e.g. "app.name"
        $config = $cache[$file];

        foreach ($segments as $segment) {
            if (!isset($config[$segment])) {
                return $default;
            }
            $config = $config[$segment];
        }

        return $config;
    }
}

if (!function_exists('AddModuleFunct')) {
    function AddModuleFunct($module = null, $funct = null, $callback = null)
    {
        if (!$module || !$funct || !$callback) {
            return null;
        }

        $channel = 'module:' . strtolower($module);

        Hooks($channel)->add(function ($methods) use ($funct, $callback) {

            $methods[$funct] = $callback;

            return $methods;

        });

        return true;
    }
}

// if (!function_exists('AddModuleFunct')) {
//     function AddModuleFunct($module = null, $funct = null, $callback = null){
//         if($module && $funct && $callback){
//             return Hooks()->addKlassFunct( $module, $funct, $callback );
//         }
//         return null;
//     }
// }

// if (!function_exists('ModuleFunct')) {
//     function ModuleFunct($module = null, $funct = null, $params = []){
//         if($module && $funct){
//             return Hooks()->getKlassFunct($module,$funct,$params);
//         }
//         return null;
//     }
// }

if (!function_exists('ModuleFunct')) {
    function ModuleFunct($module = null, $funct = null, $params = [])
    {
        if (!$module || !$funct) {
            return null;
        }

        $channel = 'module:' . strtolower($module);

        $methods = Hooks($channel)->call([]);

        if (!isset($methods[$funct])) {
            return null;
        }

        $callable = $methods[$funct];

        if (!is_callable($callable)) {
            return null;
        }

        return call_user_func_array($callable, $params);
    }
}


if (!function_exists('formatFileSize')) {
    function formatFileSize($bytes, $decimals = 2) {
        $sizeUnits = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        if ($bytes == 0) {
            return '0 B';
        }
        $factor = floor((strlen($bytes) - 1) / 3);
        $formattedSize = $bytes / pow(1024, $factor);
        return sprintf("%.{$decimals}f %s", $formattedSize, $sizeUnits[$factor]);
    }
}


if (!function_exists('formatDateStandard')) {
    function formatDateStandard($date){
        // return date( "d/m/Y H:i", $date);
        return date( $date);
    }
}

if (!function_exists('requireToVar')) {
	function requireToVar($file = null, $args = []){
		ob_start();
		extract($args);
		// die($file);
		if($file){  
			require($file);
			return ob_get_clean();
		}
	}
}

if (!function_exists('mHelper')){
    /**
     * @return HelperProxy
     */
    function mHelper(): \BoraSlim\Core\Support\HelperResolver
    {
        return \BoraSlim\Core\Support\HelperResolver::class;
    }
}

//2025 Dec
function tap(mixed $value, callable $callback): mixed {
    $callback($value);
    return $value;
}

//Cache 
function cache(): \BoraSlim\Core\Modules\App\Cache\Cache
{
    return new \BoraSlim\Core\Modules\App\Cache\Cache();
}

function cache_get(string $key, mixed $default = null): mixed {
    return cache()->get($key, $default);
}

function cache_set(string $key, mixed $value, int $ttl = 60): void {
    cache()->set($key, $value, $ttl);
}

function cache_remember(string $key, int $ttl, callable $callback): mixed {
    return cache()->remember($key, $ttl, $callback);
}

function cache_remember_forever(string $key, callable $callback): mixed {
    return cache()->rememberForever($key, $callback);
}

function cache_forget(string $key): void {
    cache()->delete($key);
}

if(!function_exists('abort')){
    function abort(int $status, string $message = '')
    {
        http_response_code($status);
        echo json_encode([
            'ok' => false,
            'error' => $message
        ]);
        exit;
    }
}

/* Translator */
if (!function_exists('i18n_current_lang')) {
    function i18n_current_lang(): string
    {
        $lang = 'en';
        // EARLY bootstrap (before myApp / ModManage)
        if (isset($_SESSION['siteprefs'])) {
            $prefs = unserialize($_SESSION['siteprefs']);
            // jsonExit($prefs);
            $lang = $prefs['language'];
        }

        if($prefs = \BoraSlim\Core\Modules\Ui\Controllers\Api\UserprefsController::all(true)){
            // jsonExit($prefs);
            $lang = getIfSet($prefs['language'],'en');
        }

        return $lang;
    }
}

use BoraSlim\Core\I18n\I18nBootstrap;
if(!function_exists('getTranslator')){
    function getTranslator(){
        return I18nBootstrap::translator();
    }
}

if (!function_exists('__t')) {
    function __t(
        string $key,
        ?string $lang = null,
        ?string $default = null,
        array $replace = []
    ): string {
        $translator = I18nBootstrap::translator();

        $lang = $lang ?? i18n_current_lang();

        $text = $translator->translate($key, $lang, $default);

        // Apply replacements
        if(!empty($replace)){
            // dieVal($text);
            $text = preg_replace_callback('/\{\{(\w+)\}\}/', function ($matches) use ($replace) {
                return $replace[$matches[1]] ?? $matches[0];
            }, $text);
        }

        return $text;
    }
}


if (!function_exists('i18n_register_core')) {
    function i18n_register_core(string $domain): void
    {
        $translator = I18nBootstrap::translator();
        $loader     = I18nBootstrap::loader();

        $lang = i18n_current_lang();

        // Always register merged EN
        $translator->register(
            $domain,
            'en',
            $loader->loadMergedCore($domain, 'en')
        );

        if ($lang !== 'en') {
            $messages = $loader->loadMergedCore($domain, $lang);
            if ($messages) {
                $translator->register($domain, $lang, $messages);
            }
        }
    }
}

if (!function_exists('i18n_register_module')) {
    function i18n_register_module(string $module): void
    {
        $translator = I18nBootstrap::translator();
        $loader     = I18nBootstrap::loader();

        $lang = i18n_current_lang();
        $domain = strtolower($module);

        $translator->register(
            $domain,
            'en',
            $loader->loadModule($domain, 'en')
        );

        if ($lang !== 'en') {
            $messages = $loader->loadModule($domain, $lang);
            if ($messages) {
                $translator->register($domain, $lang, $messages);
            }
        }
    }
}

use BoraSlim\Core\Kernel\Modules\ModuleService;
if (!function_exists('i18n_register_auto')) {
    function i18n_register_auto(ModuleService $service): void
    {
        if ($service->isCore()) { 
            // print_r($service->getDomain().'<br>');
            i18n_register_core($service->getDomain());
        } else {
            // print_r($service->getName().'<br>');
            i18n_register_module($service->getName());
        }
    }
}

if (!function_exists('isLoggedIn')) {
    function isLoggedIn(): bool
    {
        try {

            $users = With('users');

            return (bool) $users->getManager()->isAuthenticated();

        } catch (\Throwable $e) {
            error_log($e->getMessage());
            return false;
        }
    }
}

if (!function_exists('isAdmin')) {
    function isAdmin(): bool
    {
        try {

            $users = With('users');

            if (!$users) {
                return false;
            }

            $manager = method_exists($users, 'getManager')
                ? $users->getManager()
                : null;

            if (!$manager) {
                return false;
            }

            return (bool) $manager->hasRole('administrator');

        } catch (\Throwable $e) {
            return false;
        }
    }
}

if(!function_exists('timeAgo')){
    function timeAgo($datetime): string
    {
        if (!$datetime) return '';

        $time = is_numeric($datetime) ? $datetime : strtotime($datetime);
        $diff = time() - $time;

        if ($diff < 60) return 'now';
        if ($diff < 3600) return floor($diff / 60) . 'm';
        if ($diff < 86400) return floor($diff / 3600) . 'h';
        if ($diff < 604800) return floor($diff / 86400) . 'd';
        if ($diff < 2592000) return floor($diff / 604800) . 'w';

        return date('M j', $time); // fallback
    }
}

if(!function_exists('getPropertyType')){
    function getPropertyType(object $obj, string $prop): ?string
    {
        if (!property_exists($obj, $prop)) return null;

        $ref = new ReflectionProperty($obj, $prop);
        $type = $ref->getType();

        if (!$type) return null;

        // Named type (most common case)
        if ($type instanceof ReflectionNamedType) {
            return $type->getName();
        }

        // Union type (PHP 8+)
        if ($type instanceof ReflectionUnionType) {
            $types = array_map(fn($t) => $t->getName(), $type->getTypes());
            return implode('|', $types); // e.g. "int|string"
        }

        // Intersection type (PHP 8.1+)
        if ($type instanceof ReflectionIntersectionType) {
            $types = array_map(fn($t) => $t->getName(), $type->getTypes());
            return implode('&', $types);
        }

        return null;
    }
}

if(!function_exists('core')){
    function core(): \BoraSlim\Core\Container
    {
        static $app;

        if (!$app) {
            $app = new \BoraSlim\Core\Container();
        }

        return $app;
    }

    function resolve(string $key)
    {
        return core()->make($key);
    }
}

if(!function_exists('getBrowserID')){
    function getBrowserID(){
        if(!empty(userID())){
            return md5(userID());
        }
        
        $browser = (object) getBrowserDetails();
        $userIP = getUserIpAddr();
        $userID = '';
        if(isset($_SESSION['loggedIn'])){
            if($sessData = @unserialize($_SESSION['loggedIn'])){
                    $userID = $sessData->id;
            }
        }

        return md5($browser->browser_name.$userID.$userIP);
    }
}

if(!function_exists('getBrowserDetails')){
    function getBrowserDetails($enc = false){
        $Browser = new BoraSlim\Core\Utils\BrowserDetection();
        // $useragent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Mobile Safari/537.36';
        $useragent = $_SERVER['HTTP_USER_AGENT'];
        $result = $Browser->getAll($useragent);
        // print_r($result);
        
        if($enc){
            return md5(json_encode($result));
        }

        return $result;
    }
}

// Ctx
if(!function_exists('ctx')){
    function ctx(): \BoraSlim\Core\Ctx
    {
        return \BoraSlim\Core\Ctx::instance();
    }
}

//Domain results
if (!function_exists('dr')) {
    function dr(): string
    {
        return \BoraSlim\Core\Domain\DomainResult::class;
    }
}

// Widgets
if (!function_exists('widgets')) {

    function widgets(): \BoraSlim\Core\Kernel\Widgets\WidgetRegistry
    {
        if (!ctx()->has(\BoraSlim\Core\Kernel\Widgets\WidgetRegistry::class)) {
            ctx()->set(
                \BoraSlim\Core\Kernel\Widgets\WidgetRegistry::class,
                new \BoraSlim\Core\Kernel\Widgets\WidgetRegistry()
            );
        }

        return ctx()->get(\BoraSlim\Core\Kernel\Widgets\WidgetRegistry::class);
    }
}

// Forms
if(!function_exists('forms')){
    function forms(): \BoraSlim\Core\Kernel\Forms\FormRegistry
    {
        if (!ctx()->has(\BoraSlim\Core\Kernel\Forms\FormRegistry::class)) {
            ctx()->set(
                \BoraSlim\Core\Kernel\Forms\FormRegistry::class,
                new \BoraSlim\Core\Kernel\Forms\FormRegistry()
            );
        }

        return ctx()->get(\BoraSlim\Core\Kernel\Forms\FormRegistry::class);
    }
}

// Channels
if (!function_exists('channels')) {

    function channels(): \BoraSlim\Core\Modules\Notifications\Services\ChannelRegistry
    {
        if (!ctx()->has(\BoraSlim\Core\Modules\Notifications\Services\ChannelRegistry::class)) {
            ctx()->set(
                \BoraSlim\Core\Modules\Notifications\Services\ChannelRegistry::class,
                new \BoraSlim\Core\Modules\Notifications\Services\ChannelRegistry()
            );
        }

        return ctx()->get(\BoraSlim\Core\Modules\Notifications\Services\ChannelRegistry::class);
    }
}

// Routes
if (!function_exists('routes')) {

    function routes(): \BoraSlim\Core\Routing\RouteRegistry
    {
        if (!ctx()->has(\BoraSlim\Core\Routing\RouteRegistry::class)) {
            ctx()->set(
                \BoraSlim\Core\Routing\RouteRegistry::class,
                new \BoraSlim\Core\Routing\RouteRegistry()
            );
        }

        return ctx()->get(\BoraSlim\Core\Routing\RouteRegistry::class);
    }
}

//Queue 
if(!function_exists('queue')){
    function queue(): \BoraSlim\Core\Infrastructure\Queue\DatabaseQueue
    {
        return ctx()->make(\BoraSlim\Core\Infrastructure\Queue\DatabaseQueue::class);
    }
}

//Context menu
if(!function_exists('contextMenu')){
    function contextMenu(): \BoraSlim\Core\Modules\Ui\Services\ContextMenu
    {
        return ctx()->make(\BoraSlim\Core\Modules\Ui\Services\ContextMenu::class);
    }
}

// Menus
if(!function_exists('menus')){
    function menus(): \BoraSlim\Core\Ui\Menus\MenuManager
    {
        return ctx()->make(\BoraSlim\Core\Ui\Menus\MenuManager::class);
    }
}
if(!function_exists('menuCtx')){
    function menuCtx(...$params): \BoraSlim\Core\Ui\Menus\MenuContext
    {
        return ctx()->make(\BoraSlim\Core\Ui\Menus\MenuContext::class);
    }
}


// Dropdown
if(!function_exists('dropdown')){
    function dropdown(): \BoraSlim\Core\Modules\Ui\Services\DropdownPanel
    {
        return ctx()->make(\BoraSlim\Core\Modules\Ui\Services\DropdownPanel::class);
    }
}

// API
if (!function_exists('api')) {
    function api(): \BoraSlim\Core\Http\ApiRegistry
    {
        $ctx = ctx();

        if (!$ctx->bound('api.registry')) {
            $ctx->bind('api.registry', fn() => new \BoraSlim\Core\Http\ApiRegistry());
        }

        return $ctx->make('api.registry');
    }
}

if (!function_exists('api_responder')) {
    function api_responder(?\BoraSlim\Core\Http\Responders\HttpStatusMapper $mapper = null): \BoraSlim\Core\Http\Responders\ApiResponder
    {
        $role = myApp()->getFeature('permissions')->getCurrentRole();
        return new \BoraSlim\Core\Http\Responders\ApiResponder(
            I18nBootstrap::translator(),
            $mapper ?? new \BoraSlim\Core\Http\Responders\DefaultHttpStatusMapper(),
            new \BoraSlim\Core\Http\RequestContext(
                i18n_current_lang(),
                $role??'Guest'
            )
        );
    }
}

if (!function_exists('validate')) {
    function validate(array $data, array $rules): array
    {
        $validator = new \BoraSlim\Core\Support\Validator($data, $rules);

        if ($validator->fails()) {
            throw new \DomainException(json_encode([
                'type' => 'validation',
                'errors' => $validator->errors()
            ]));
        }

        return $data;
    }
}

if(!function_exists('slugify')){

    /**
     * Convert text into URL-safe slug
     *
     * Example:
     *
     * slugify('Music Festival 2026');
     * // music-festival-2026
     */

    function slugify(
        ?string $text,
        string $separator = '-'
    ): string {

        $text = trim(
            (string)$text
        );

        if($text === ''){
            return '';
        }

        /*
        |--------------------------------------------------------------------------
        | Transliterate UTF-8
        |--------------------------------------------------------------------------
        */

        $text = iconv(
            'UTF-8',
            'ASCII//TRANSLIT//IGNORE',
            $text
        );

        /*
        |--------------------------------------------------------------------------
        | Lowercase
        |--------------------------------------------------------------------------
        */

        $text = strtolower($text);

        /*
        |--------------------------------------------------------------------------
        | Remove apostrophes
        |--------------------------------------------------------------------------
        */

        $text = str_replace(
            ["'", "`"],
            '',
            $text
        );

        /*
        |--------------------------------------------------------------------------
        | Replace non alphanumeric
        |--------------------------------------------------------------------------
        */

        $text = preg_replace(

            '/[^a-z0-9]+/',

            $separator,

            $text
        );

        /*
        |--------------------------------------------------------------------------
        | Remove duplicate separators
        |--------------------------------------------------------------------------
        */

        $escaped = preg_quote(
            $separator,
            '/'
        );

        $text = preg_replace(

            '/'.$escaped.'+/',

            $separator,

            $text
        );

        /*
        |--------------------------------------------------------------------------
        | Trim separators
        |--------------------------------------------------------------------------
        */

        $text = trim(
            $text,
            $separator
        );

        return $text;
    }
}

use BoraSlim\Core\Support\Str;

if (!function_exists('media')) {

    /**
     * Generate media viewer URL.
     *
     * @param int|string|null $media
     * @param string|null $size
     * @return string|null
     */
    function media(
        int|string|null $media,
        ?string $size = null
    ): ?string {

        if (empty($media)) {
            return null;
        }

        $sizes = [

            'thumbnail' => 't',
            'thumb'     => 't',
            't'         => 't',

            'small'     => 's',
            's'         => 's',

            'medium'    => 'm',
            'm'         => 'm',

            'large'     => 'l',
            'l'         => 'l',

            'original'  => null,
            'full'      => null
        ];

        $size = $size
            ? ($sizes[strtolower($size)] ?? null)
            : null;

        $url = 'viewer/media/' . $media;

        if ($size) {
            $url .= '/' . $size;
        }

        return $url;
    }
}