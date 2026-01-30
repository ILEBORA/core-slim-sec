<?php

class AppJsKernel
{
    protected string $root;
    protected string $env;
    protected array $config = [];

    public function __construct(
        string $rootDir,
        string $env = 'boraslim'
    ) {
        $this->root = rtrim($rootDir, '/');
        $this->env  = $env;

        // EnvLoader::load($this->root, $this->env);
    }

    /**
     * Entry point
     */
    public function serve(): void
    {
        $this->sendHeaders();

        $this->bootstrap();
        $this->emitEngineSettings();
        $this->emitHooks();
        $this->emitConfig();
        $this->emitSessionWatchers();
    }

    protected function sendHeaders(): void
    {
        header("Content-Type: application/javascript");
        header("Cache-Control: max-age=604800, public");
    }

    protected function bootstrap(): void
    {
        require_once __DIR__ . '/JsHooks.php';
        require_once __DIR__ . '/assets_helper.php';
        require $this->root . '/src/engine.php';
    }

    protected function emitEngineSettings(): void
    {
        $appKey = $_SESSION['APP_KEY'] ?? '';

        echo <<<JS
var mPGs = mPGs || {}; mPGs.tools = mPGs.tools || {}; mPGs.widgets = mPGs.widgets || {};
var appUI = {};
var plugins = {};
window.settings = { jsVersion: 1 };

const engineSettings = {
    cachescripts: 1,
    loadstatustext: "<img src='assets/images/icons/ajax.gif' /> Requesting content...",
    loadpreloader: '<div class="spinner"><div class="rect1"></div><div class="rect2"></div><div class="rect3"></div><div class="rect4"></div><div class="rect5"></div></div>',
    c: '{$appKey}'
};
JS;
    }

    protected function emitHooks(): void
    {
        $perms = $_SESSION['perms'] ?? [];
        $role  = $_SESSION['role'] ?? 'Guest';

        $hooks = new JsHooks($perms, $role);

        autoIncludeCoreJs($hooks);

        // Client override hook (optional)
        $hooks->register('client', 'client_app.js');

        $hooks->addJs([
            'jquery','jquery_global','ilebora_or','boracache','borahooks',
            'boraplugin','boraevents','borapopup','logger','callbora',
            'elements','plugins','colorpicker','boraalertsv2',
            'alertify','select2','mainjs','client'
        ]);

        $this->loadModuleJs($hooks);

        echo $hooks->dispatchJs();

        echo <<<JS
var include = getNS('ILEBORA.include'),
    use = getNS('ILEBORA.use'),
    from = getNS('ILEBORA.from');
JS;
    }

    protected function loadModuleJs(JsHooks $hooks): void
    {
        $cacheFile = BASE_DIR . '/.cache/enabled_modules.php';
        $modules = file_exists($cacheFile) ? include $cacheFile : [];

        foreach ($modules as $module) {
            if (!empty($module['js'])) {
                $key = strtolower($module['name']);
                $hooks->register($key, BASE_DIR . $module['js']);
                $hooks->addJs([$key]);
            }
        }
    }

    protected function emitConfig(): void
    {
        $userID = userID();

        $config = [
            "env"           => $_ENV['ENV_DEVELOPMENT'],
            "myNs"          => "assets.plugins.addons",
            "myNsWdg"       => "src.Views._shared.widgets",
            "myNsPgs"       => "src.Views._shared.pages",
            "myNsRts"       => "routes.special.",
            "mediaFolder"   => "assets/images/icons/media/",
            "prjName"       => $_ENV['PRJCTN'],
            "prjVersion"    => "1.0.0",
            "prjFolder"     => $_ENV['PRJCTN'],
            "cryptUpdates"  => false,
            "cryptRoutes"   => true,
            "bld"           => "views",
            "jsVersion"     => "1.0.0",
            "lang"          => "en",
            "p"             => $_ENV['APP_ID'],
            "u"             => $_SESSION['APP_KEY'] ?? '',
            "sessTime"      => $_ENV['SESSION_TIME'],
            "pageContainer" => "#page_container",
            "uID"           => $userID,
            "bID"           => CHANNEL_ID ?? '',
            "baseUrl"       => BASE_URL ?? '',
            "client_session"=> $_SESSION['client'] ?? md5(time()),
            "sseID"         => $_SESSION['user_id'] ?? md5(time())
        ];

        $encrypted = CryptoJSAesEncrypt(json_encode($config));

        echo <<<JS
var cE = '{$encrypted}';
updateCe(cE);
var sFld = rd('myNs'), wFld = rd('myNsWdg'), pFld = rd('myNsPgs');
ILEBORA(sFld);
setTimeout(() => authChannelInit(rd('bID')), 0);
JS;
    }

    protected function emitSessionWatchers(): void
    {
        if (!($_SESSION['persist'] ?? false)) {
            echo <<<JS
if (getCookie('persistSess') != 1) {
    listenCookieChange('authSessID', function () {
        alertBora.notify('Session Expired!', 'error', 20);
        mPGs.logoutUser();
    });
}
JS;
        }
    }
}