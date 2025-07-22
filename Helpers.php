<?php
use BoraSlim\Core\App;
use BoraSlim\Core\DB;
use BoraSlim\Core;

if (!function_exists('newSession')) {
    function newSession(array $settings = []) {
        if (session_status() === PHP_SESSION_NONE) {

            header('P3P: CP="CAO PSA OUR"');

            ini_set('session.cookie_samesite', $settings['samesite'] ?? 'None');
            ini_set('session.cookie_secure', $settings['secure'] ?? 'true');
            session_cache_limiter($settings['cache_limiter'] ?? 'private, must-revalidate');
            session_cache_expire($settings['cache_expire'] ?? 30);
            
            session_name($settings['name'] ?? 'ACS');
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
        $rows = appDB()->runQuery("SELECT `method`, `uri`, `controller`, `action` FROM `app_dynamic_routes` WHERE `enabled` = 1");
        return $rows->fetch_all(MYSQLI_ASSOC);
    }
}

if (!function_exists('processDBRoutes')) {
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

function userID(){
    global $userID; //TODO:: get userID
    
    return $userID; 
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

if (!function_exists('Feature')) {
    function Feature(): \BoraSlim\Core\Helpers\FeatureResolver
    {
        static $resolver = null;
        if ($resolver === null) {
            $resolver = new \BoraSlim\Core\Helpers\FeatureResolver();
        }
        return $resolver;
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
        $base_url = '/';

        if ($instance === null) {
            $instance = new View();
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
    function getVersion($folder = null) {
        $basePath = $folder ?? '.';
        $versionFile = rtrim($basePath, '/\\') . '/.config/.version';

        if (!file_exists($versionFile)) {
            return 'v1.0.0'; // default version
        }

        return trim(file_get_contents($versionFile)) ?: 'v1.0.0'; // fallback if file is empty
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
    function hasPermission($perm, $sub = null, $force_create = false){
        // $class = Manage()->permission->getInstance();
        // return $class->hasPermission($perm, $sub, $force_create);
        $class = Feature()->permissions->getInstance();  // note: key "permissions" must match registration
        return $class->hasPermission($perm, $sub, $force_create);
    }
}

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
