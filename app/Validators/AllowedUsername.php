<?php
namespace App\Validators;

use Illuminate\Routing\Router;
use Illuminate\Config\Repository;
use Illuminate\Filesystem\Filesystem;

class AllowedUsername
{
    /**
     * The router instance used to check the username against application routes.
     *
     * @var \Illuminate\Routing\Router
     */
    private $router;
    /**
     * The filesystem class used to retrieve public files and directories.
     *
     * @var \Illuminate\Filesystem\Filesystem
     */
    private $files;
    /**
     * The config repository used to retrieve reserved usernames.
     *
     * @var \Illuminate\Config\Repository
     */
    private $config;
    /**
     * Create a new allowed username validator instance.
     *
     * @param \Illuminate\Routing\Router $router
     * @param \Illuminate\Filesystem\Filesystem $files
     * @param \Illuminate\Config\Repository $config
     */
    public function __construct(Router $router, Filesystem $files, Repository $config)
    {
        $this->config = $config;
        $this->router = $router;
        $this->files = $files;
    }
    /**
     * Validate whether the given username is allowed.
     *
     * @param  string  $attribute
     * @param  string  $username
     * @return bool
     */
    public function validate($attribute, $username)
    {
        $username = trim(strtolower($username));

        if ($this->isReservedUsername($username)) {
            return false;
        }
        if ($this->matchesRoute($username)) {
            return false;
        }
        if ($this->matchesPublicFileOrDirectory($username)) {
            return false;
        }

        if(!$this->isValidUsername($username)) {
            return false;
        }

        return true;
    }
    /**
     * Determine whether the given username is in the reserved usernames list.
     *
     * @param  string  $username
     * @return bool
     */
    private function isReservedUsername($username)
    {
        return in_array($username, $this->config->get('auth.reserved_usernames'));
    }
    /**
     * Determine whether the given username matches an application route.
     *
     * @param  string  $username
     * @return bool
     */
    private function matchesRoute($username)
    {
        foreach ($this->router->getRoutes() as $route) {
            if (strtolower($route->uri) === $username) {
                return true;
            }
        }
        return false;
    }
    /**
     * Determine whether the given username matches a public file or directory.
     *
     * @param  string  $username
     * @return bool
     */
    private function matchesPublicFileOrDirectory($username)
    {
        foreach ($this->files->glob(public_path().'/*') as $path) {
            if (strtolower(basename($path)) === $username) {
                return true;
            }
        }
        return false;
    }

    private function isValidUsername($username)
    {
        return preg_match('/^[A-Za-z0-9_]{1,15}$/', $username);
    }
}