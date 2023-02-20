<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once __DIR__ . '/../vendor/autoload.php';

use eru123\Router\Router;
use eru123\webtools\WebTools;

$api = (new Router)->base('/api/v1/webtools')->add(WebTools::use_route());
(new Router)->base('/')->add($api)->run();