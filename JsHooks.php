<?php
// cores/Hooks.php
use MatthiasMullie\Minify as Minify;

class JsHooks {
    private array $registry = [];   // name => ['path' => 'assets/js/modules/chat.js', 'perm' => ['AppAccess'=>'chat']]
    private array $queue = [];      // names requested: addJs(...)
    private array $perms = [];      // user permissions (decoded)

    public function __construct(array $perms) {
        $this->perms = $perms;
    }
    
    // Register available plugins (typically at bootstrap)
    public function register(string $name, string $path, array $perm = []): self {
        $this->registry[$name] = ['path' => $path, 'perm' => $perm];
        return $this;
    }

    // Add plugin names to load
    public function addJs(array $names): self {
        foreach ($names as $n) { $this->queue[$n] = true; }
        return $this;
    }

    // Permission helper
    private function allowed(string $name): bool {
        if (!isset($this->registry[$name])) return false;
        $need = $this->registry[$name]['perm'] ?? [];
        if (!$need) return true; // no requirement
        // expect structure like $perms[$role][$permKey][$subKey] === true
        foreach ($need as $permKey => $subKey) {
            if (!isset($this->perms[$this->role][$permKey][$subKey]) || $this->perms[$this->role][$permKey][$subKey] !== true) {
                return false;
            }
        }
        return true;
    }

    private function loadPermScripts(): void {
        foreach ($this->perms as $group => $permList) {
            foreach ($permList as $perm) {
                // APP-LEVEL PATH
                $appPath = BASE_DIR . "/assets/js/perms/{$group}/{$perm}.js";

                // MODULE-LEVEL PATH (ModuleName case-sensitive)
                $modulePath = BASE_DIR . "/Modules/" . ucfirst($group) . "/Assets/js/perms/{$perm}.js";

                if (file_exists($appPath)) {
                    $name = "perm_app_{$group}_{$perm}";
                    $this->register($name, $appPath)->addJs([$name]);
                } elseif (file_exists($modulePath)) {
                    $name = "perm_mod_{$group}_{$perm}";
                    $this->register($name, $modulePath)->addJs([$name]);
                }
            }
        }
    }

    // Emit a compact JS bootloader that loads only allowed plugins (via serve_js.php)
    public function dispatchJs(): string {
        $this->loadPermScripts();

        $out = '';
        $allowed = [];
        $content = '';

        // breakWith($this->registry);
        foreach (array_keys($this->queue) as $name) {
            if ($this->allowed($name)) $allowed[] = $name;
            if(isset($this->registry[$name])){
                $file = $this->registry[$name]['path'];
                // "modules/$name.js";
                // print_r($file.'<br>');
                if(file_exists($file)){
                    $content .= requireToVarInit($file);
                }
            }
        }
        $jsonNames = json_encode($allowed);
        // $out .= "console.log($jsonNames));";
        // A small loader that:
        //  - requests each plugin through serve_js.php (obfuscated/permission-checked)
        //  - feeds it into ILEBORA.include (which returns module.exports)
        //  - exposes each module under window.plugins[name]
        //  - emits a final "plugins:ready" event
        // ---- Obfuscate (simple): base64 wrap + eval ----
        $encoded = base64_encode($content);//base64_encode($raw);
        // OPTIONAL: very tiny “minify”
        $encoded = $encoded; // hook your obfuscator here

        // Wrap as a CommonJS-like module factory that returns module.exports
        
        // $out .= "/* {$name} (served) */\n";
        // $out .= "(function(ILEBORA, module, exports){\n";
        // $out .= "  // obfuscated payload\n";
        // $out .= "  (function(){ eval(atob('{$encoded}')); })();\n";
        // $out .= "  return module.exports;\n";
        // $out .= "});\n";
        // $out .= "alert('final');";

        // $out .= "console.log('here hooks');";
        $out .= $content;
        // $out = $this->obfuscateJs($out);
        // $out = $this->minifyScript($out);

        return $out;
    }


    public function obfuscateJs($jsCode) {
        // Step 1: Extract all strings (single/double quotes)
        preg_match_all('/(["\'])(.*?)\1/', $jsCode, $matches);

        $lookup = [];
        $map = [];
        $replaced = $jsCode;

        // Step 2: Build hex strings and map them to array indexes
        foreach ($matches[2] as $i => $str) {
            if (!isset($map[$str])) {
                $hex = '';
                for ($j = 0; $j < strlen($str); $j++) {
                    $hex .= "\\x" . strtoupper(dechex(ord($str[$j])));
                }
                $map[$str] = count($lookup); // store index
                $lookup[] = "\"$hex\"";      // push into array
            }
        }

        // Step 3: Replace strings in JS code with lookup refs
        foreach ($map as $str => $index) {
            // Replace "string" or 'string'
            $replaced = preg_replace(
                '/(["\'])' . preg_quote($str, '/') . '\1/',
                "_0xLOOKUP[$index]",
                $replaced
            );
        }

        // Step 4: Build final obfuscated output
        $varName = "_0x" . substr(md5(mt_rand()), 0, 4);
        $output  = "var $varName = [\n    " . implode(",\n    ", $lookup) . "\n];\n\n";
        $output .= str_replace("_0xLOOKUP", $varName, $replaced);

        return $output;
    }

    public function minifyScript($script){

        $minifier = new Minify\JS();
        $minifier->add($script);
        return $minifier->minify();

    }

    public function obfuscateJsO($content) {
        // $content = file_get_contents($file);
        $encoded = base64_encode($content);
        return "eval(atob('{$encoded}'));";
    }
}
