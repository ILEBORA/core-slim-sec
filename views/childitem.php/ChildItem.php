<?php
namespace BoraSlim\Core\Modules;

use BoraSlim\Core\Utils\Preferences;

abstract class ChildItem {
    // Optional traits (DB, Image, Upload) can be used in child classes
    // protected string $parentClass = 'users'; //The module and repo
    // optional explicit override
    // protected $repositoryClass = "\\Modules\\Special\\Repositories\\CustomUserRepository";
    protected $data = [];
    protected $repository;

    public function __construct($item = null, $type = 'id', $repository = null,) {
        $this->repository = $repository ?? $this->resolveRepository();
        if ($item !== null) {
            $this->loadBy($type, $item);
        }
    }

    // ------------------------
    // Hydration & Loading
    // ------------------------
    public function hydrate(array $data) {
        $this->data = $data;
        return $this;
    }

    public function loadBy(string $field, $value) {
        if (!$this->repository) throw new \Exception("Repository not set");
        $data = $this->repository->getByField($field, $value);
        
        return $data ? $this->hydrate($data) : null;
    }

    // ------------------------
    // CRUD Helpers
    // ------------------------
    abstract protected function beforeSave();
    abstract protected function afterSave();


    public function save() {
        if (!$this->repository) {
            throw new \Exception("Repository not set");
        }

        // Pre-save hook
        $this->beforeSave();

        // Determine create vs update
        if (isset($this->data['id'])) {
            $result = $this->repository->update($this->data['id'], $this->data);
        } else {
            $result = $this->repository->create($this->data);
            if ($result) {
                $this->data['id'] = $result; // ensure ID is updated in-memory
            }
        }

        // Post-save hook
        $this->afterSave();

        return $result;
    }

    // public function saveO() {
    //     if (!$this->repository) throw new \Exception("Repository not set");
    //     if (isset($this->data['id'])) {
    //         return $this->repository->update($this->data['id'], $this->data);
    //     }
    //     return $this->repository->create($this->data);
    // }

    // public function delete($id = null) {
    //     $id = $id ?? ($this->data['id'] ?? null);
    //     if (!$id) throw new \Exception("ID required for delete");
    //     return $this->repository->delete($id);
    // }

    protected function beforeDelete() {}
    protected function afterDelete() {}
    public function delete()
    {
        if (!isset($this->data['id'])) {
            throw new \Exception("Cannot delete unsaved item");
        }

        $id = $this->data['id'];
        $this->beforeDelete();
        $result = $this->repository->delete($id);
        $this->afterDelete();

        if ($this->dispatcher && method_exists($this->dispatcher, 'trigger')) {
            $this->dispatcher->trigger("item.deleted", $this);
            $this->dispatcher->trigger(strtolower(static::class) . ".deleted", $this);
        }

        return $result;
    }


    public function existsByField(string $field, $value): bool {
        if (!$this->repository) throw new \Exception("Repository not set");
        return (bool)$this->repository->exists($field, $value);
    }

    // ------------------------
    // Middleware: Process Raw DB Data
    // ------------------------
    abstract protected function process(): array;

    abstract protected function add(array $post);
    
    abstract protected function edit(array $post);

    public function getItem(bool $asObject = false) {
        $item = $this->process();
        return $asObject ? (object)$item : $item;
    }

    // ------------------------
    // Hydration / Accessors
    // ------------------------
    public function setData(array $data)
    {
        $this->data = $data;
        return $this;
    }

    public function getData(): array
    {
        return $this->data;
    }
    // ------------------------
    // Magic Accessors
    // ------------------------
    public function __get($key) {
        return $this->data[$key] ?? null;
    }

    public function __set($key, $value) {
        $this->data[$key] = $value;
    }

    public function toArray(): array {
        return $this->data;
    }

    public function toObject(): object {
        return (object)$this->data;
    }

    // ------------------------
    // Utilities
    // ------------------------
    protected $repositoryInstance = null;
    protected function resolveRepository() {
        // Return cached instance if already resolved
        if ($this->repositoryInstance) return $this->repositoryInstance;

        // 1. Use explicit repository class if provided
        if (property_exists($this, 'repositoryClass') && !empty($this->repositoryClass)) {
            if (class_exists($this->repositoryClass)) {
                return $this->repositoryInstance = new $this->repositoryClass();
            } else {
                throw new \Exception("Repository class '{$this->repositoryClass}' does not exist");
            }
        }

        // 2. Use parentClass to auto-resolve
        if (!property_exists($this, 'parentClass') || empty($this->parentClass)) {
            throw new \Exception("Child class " . get_class($this) . " must define \$parentClass or \$repositoryClass");
        }

        $module = $this->parentClass;

        // Check client module first (override), then core
        $namespaces = [
            "\\Modules\\{$module}\\Repositories\\{$module}Repository",
            "\\BoraSlim\\Core\\Modules\\{$module}\\Repositories\\{$module}Repository"
        ];

        foreach ($namespaces as $repoClass) {
            if (class_exists($repoClass)) {
                return $this->repositoryInstance = new $repoClass();
            }
        }

        throw new \Exception("Repository class not found for module '{$module}'");
    }


    protected function filterInputs(array $allowed, array $inputs): array {
        return array_filter(
            $inputs,
            fn($key) => in_array($key, $allowed),
            ARRAY_FILTER_USE_KEY
        );
    }

    public function getNotifyContent(){
		$parent = strtolower($this->parentClass);
		return [
			'content' => 'New item for <a href="javascript:void(0)" onclick="'.$this->getPageLink().'">'.$this->id.'</a>',
			'link' => "mPGs.diagOpen('diagPop','details','$parent','".$this->id."', 'details');event.stopPropagation();"
		];
	}

    public function getPageLink(){
		$parent = strtolower($this->parentClass);
		$link = "mPGs.diagOpen('diagPop','details','$parent','".$this->id."','details')";

		return $link;
	}

    public function getItemUploadPath($default = null)
    {
        // Parent module, e.g. "Users" → "users"
        $parent = strtolower($this->parentClass);

        // Model short name, e.g. User → user
        $model = strtolower((new \ReflectionClass($this))->getShortName());
        
        // Base secure upload directory
        $base = rtrim(SECUREFOLDER, '/');

        // Full path pattern: /secure/uplds/{module}/{model}/{id}/
        $path = "{$base}/uplds/{$parent}/{$model}/{$this->id}/";

        // System root
        $root = BASE_DIR . '/';

        // Ensure folder exists
        if (!is_dir($root . $path)) {
           \App\Utils\Files::makeDir($root . $path);
        }

        // If `$default` is TRUE → return only the base model folder
        // Else return the full id path
        return $default
            ? "{$base}/uplds/{$parent}/{$model}/"
            : $path;
    }


    


    //

    public function getStaticPreferenceID(){
        if(is_null( $this->preferencesID)){
            // Parent module, e.g. "Users" → "users"
            $parent = strtolower($this->parentClass);

            // Model short name, e.g. User → user
            $model = strtolower((new \ReflectionClass($this))->getShortName());

            $this->preferencesID = Preferences::getType($model,'table',$parent);
        }
        return $this->preferencesID;
    }

    

}