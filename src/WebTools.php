<?php

namespace eru123\webtools;

use eru123\Router\Router;
use Exception;

class WebTools
{
    public static function use_route()
    {
        $router = new Router();
        $router->post('/dnslookup', [static::class, 'dnslookup']);
        $router->post('/whoislookup', [static::class, 'whoislookup']);
        $router->post('/ping', [static::class, 'ping']);
        $router->post('/traceroute', [static::class, 'traceroute']);
        $router->post('/headers', [static::class, 'headers']);
        return $router;
    }

    public static function dnslookup()
    {
        $methods_list = [
            'A' => DNS_A,
            'AAAA' => DNS_AAAA,
            'MX' => DNS_MX,
            'NS' => DNS_NS,
            'SOA' => DNS_SOA,
            'CNAME' => DNS_CNAME,
            'PTR' => DNS_PTR,
            'TXT' => DNS_TXT,
            'SRV' => DNS_SRV,
            'NAPTR' => DNS_NAPTR,
            'A6' => DNS_A6,
            'HINFO' => DNS_HINFO,
            'CAA' => DNS_CAA
        ];

        $body = Helper::request_body();
        $data = Helper::schema_validator($body, [
            'domain' => [
                'type' => 'string',
                'required' => true,
                'alias' => 'Domain',
                'regex' => '/^[\w\d\.\-]+\.[\w\d]{2,}$/',
            ],
            'method' => [
                'type' => 'enum',
                'alias' => 'Method',
                'values' => array_merge(array_keys($methods_list), ['ALL']),
                'default' => 'ALL'
            ],
            'methods' => [
                'type' => 'array',
                'alias' => 'Methods',
            ],
            'type' => [
                'type' => 'enum',
                'alias' => 'Type',
                'default' => 'group',
                'values' => ['group', 'list'],
            ]
        ]);

        $domain = $data['domain'];
        $method = $data['method'];
        $methods = $data['methods'];
        $type = $data['type'];

        if (!isset($domain)) {
            throw new Exception('Missing required field: domain', 400);
        }

        if (!empty($methods) && is_array($methods)) {
            $methods = array_intersect_key($methods_list, array_flip($methods));
        } else if (!empty($method) && is_string($method) && $method !== 'ALL') {
            $methods = [$method => $methods_list[$method]];
        } else {
            $methods = $methods_list;
        }

        $records = [];
        foreach ($methods as $method => $value) {
            $records[$method] = @dns_get_record($domain, $value) ?? [];
            if (empty($records[$method])) {
                $records[$method] = [];
            }
        }

        if (empty($type)) {
            $type = 'group';
        }

        if ($type === 'group') {
            $results = array_map(function ($record, $x = null) {
                return array_map(
                    function ($item) {
                        unset($item['type']);
                        return $item;
                    }
                    ,
                    $record
                );
            }, $records);
        } else if ($type === 'list') {
            $results = [];
            foreach ($records as $record) {
                foreach ($record as $item) {
                    $results[] = $item;
                }
            }
        } else {
            throw new Exception('Invalid type', 400);
        }

        return $results;
    }

    public static function whoislookup()
    {
        $body = Helper::request_body();

        $ip_rgx = '/^((fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|2[0-4][0-9]|1{0,1}[0-9]{0,1}[0-9])\.{3,3})(25[0-5]|2[0-4][0-9]|1{0,1}[0-9]{0,1}[0-9])|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|2[0-4][0-9]|1{0,1}[0-9]{0,1}[0-9])\.{3,3})(25[0-5]|2[0-4][0-9]|1{0,1}[0-9]{0,1}[0-9])|:((:[0-9a-fA-F]{1,4}){1,7}|:))|((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/';

        $data = Helper::schema_validator($body, [
            'ip' => [
                'type' => 'string',
                'required' => true,
                'alias' => 'Domain',
                'regex' => $ip_rgx,
            ],
        ]);

        $ip = $data['ip'];

        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            throw new Exception('Whois lookup is not supported on Windows', 500);
        }

        if (shell_exec('which whois') === '') {
            throw new Exception('Whois is not installed on the server', 500);
        }

        $whois = shell_exec("whois {$ip} | grep -v '^%' | grep -v '^#' | grep -v '^$'");

        $rgx = '/^([a-zA-Z0-9\-\_]+)\s*:\s*(.+)$/m';
        preg_match_all($rgx, $whois, $matches, PREG_SET_ORDER, 0);

        $results = [];
        foreach ($matches as $match) {
            if (isset($results[$match[1]])) {
                $results[$match[1]] .= $match[2] . ' ';
            } else {
                $results[$match[1]] = $match[2];
            }
        }

        return $results;
    }
    public static function ping()
    {
        $body = Helper::request_body();
        $host_rgx = '/^(([\w\d\.\-]+\.[\w\d]{2,})|((fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|2[0-4][0-9]|1{0,1}[0-9]{0,1}[0-9])\.{3,3})(25[0-5]|2[0-4][0-9]|1{0,1}[0-9]{0,1}[0-9])|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|2[0-4][0-9]|1{0,1}[0-9]{0,1}[0-9])\.{3,3})(25[0-5]|2[0-4][0-9]|1{0,1}[0-9]{0,1}[0-9])|:((:[0-9a-fA-F]{1,4}){1,7}|:))|((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])))$/';

        $data = Helper::schema_validator($body, [
            'host' => [
                'type' => 'string',
                'required' => true,
                'alias' => 'Host',
                'regex' => $host_rgx,
            ],
            'count' => [
                'type' => 'integer',
                'alias' => 'Count',
                'default' => 4,
                'min' => 1,
                'max' => 10,
            ],
            'timeout' => [
                'type' => 'integer',
                'alias' => 'Timeout',
                'default' => 1,
                'min' => 1,
                'max' => 10,
            ],
        ]);

        $host = $data['host'];
        $count = $data['count'];
        $timeout = $data['timeout'];

        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            throw new Exception('Ping is not supported on Windows', 500);
        }

        if (shell_exec('which ping') === '') {
            throw new Exception('Ping is not installed on the server', 500);
        }

        $ping = shell_exec("ping -c {$count} -W {$timeout} {$host}");

        $rgx = '/^(\d+)\s+packets transmitted,\s+(\d+)\s+received,\s+(\d+)%\s+packet loss,\s+time\s+(\d+)ms$/m';
        preg_match_all($rgx, $ping, $matches, PREG_SET_ORDER, 0);

        $pre = [];
        foreach ($matches as $match) {
            $pre = [
                'transmitted' => (int) $match[1],
                'received' => (int) $match[2],
                'packet_loss' => (int) $match[3],
                'total_time' => floatval($match[4]),
            ];
        }

        $rgx = '/^(?P<bytes>\d+)\s+bytes\s+from\s+(?P<from>[^\s]+)\s+\((?P<addr>[^\)]+)\):\sicmp_seq=(?P<icmp_seq>[\d]+)\s+ttl=(?P<ttl>[\d]+)\s+time=(?P<time>[\d.]+)\s+ms$/m';
        preg_match_all($rgx, $ping, $matches, PREG_SET_ORDER, 0);

        $results = [
            'bytes' => 0,
            'from' => null,
            'addr' => null,
            'ttl' => 0,
            'time' => 0,
        ];

        foreach ($matches as $match) {
            $bytes = intval($match['bytes']) + $results['bytes'];
            $ttl = intval($match['ttl']) + $results['ttl'];
            $time = floatval($match['time']) + $results['time'];
            $results = [
                'bytes' => $bytes,
                'from' => $match['from'],
                'addr' => $match['addr'],
                'ttl' => $ttl,
                'time' => $time,
            ];
        }

        $results['time'] = $results['time'] / count($matches);
        $results['ttl'] = $results['ttl'] / count($matches);
        $results['bytes'] = $results['bytes'] / count($matches);

        return array_merge($pre, $results);
    }

    public static function traceroute()
    {
        $body = Helper::request_body();

        $host_rgx = '/^(([\w\d\.\-]+\.[\w\d]{2,})|((fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|2[0-4][0-9]|1{0,1}[0-9]{0,1}[0-9])\.{3,3})(25[0-5]|2[0-4][0-9]|1{0,1}[0-9]{0,1}[0-9])|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|2[0-4][0-9]|1{0,1}[0-9]{0,1}[0-9])\.{3,3})(25[0-5]|2[0-4][0-9]|1{0,1}[0-9]{0,1}[0-9])|:((:[0-9a-fA-F]{1,4}){1,7}|:))|((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])))$/';

        $data = Helper::schema_validator($body, [
            'host' => [
                'type' => 'string',
                'required' => true,
                'alias' => 'Host',
                'regex' => $host_rgx,
            ],
            'count' => [
                'type' => 'integer',
                'alias' => 'Count',
                'default' => 4,
                'min' => 1,
                'max' => 10,
            ],
            'timeout' => [
                'type' => 'integer',
                'alias' => 'Timeout',
                'default' => 1,
                'min' => 1,
                'max' => 10,
            ],
        ]);

        $host = $data['host'];
        $count = $data['count'];
        $timeout = $data['timeout'];

        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            throw new Exception('Traceroute is not supported on Windows', 500);
        }

        if (shell_exec('which traceroute') === '') {
            throw new Exception('Traceroute is not installed on the server', 500);
        }

        $traceroute = shell_exec("traceroute -n -q {$count} -w {$timeout} {$host}");

        $rgx = '/^(\d+)\s+([\w\d\.\-]+\.[\w\d]{2,})\s+\(([\w\d\.\-]+\.[\w\d]{2,})\)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)$/m';

        preg_match_all($rgx, $traceroute, $matches, PREG_SET_ORDER, 0);

        $results = [];

        foreach ($matches as $match) {
            $results[] = [
                'hop' => $match[1],
                'host' => $match[2],
                'ip' => $match[3],
                'min' => $match[4],
                'avg' => $match[5],
                'max' => $match[6],
                'mdev' => $match[7],
            ];
        }

        return $results;
    }

    public static function headers()
    {
        $body = Helper::request_body();
        $data = Helper::schema_validator($body, [
            'url' => [
                'type' => 'string',
                'required' => true,
                'alias' => 'URL',
                'regex' => '/^(?P<protocol>https?):\/\/(?P<host>((fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|2[0-4][0-9]|1{0,1}[0-9]{0,1}[0-9])\.{3,3})(25[0-5]|2[0-4][0-9]|1{0,1}[0-9]{0,1}[0-9])|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|2[0-4][0-9]|1{0,1}[0-9]{0,1}[0-9])\.{3,3})(25[0-5]|2[0-4][0-9]|1{0,1}[0-9]{0,1}[0-9])|:((:[0-9a-fA-F]{1,4}){1,7}|:))|((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))|([\w\d\.\-]+\.[\w\d]{2,}))(?P<uri>\/.*)?$/'
            ],
        ]);

        $url = $data['url'];
        $headers = get_headers($url, 1);

        $score_map = [
            'SS' => 100,
            'S' => 95,
            'A+' => 90,
            'A' => 85,
            'B+' => 80,
            'B' => 75,
            'C' => 70,
        ];

        $security_headers = [
            'Strict-Transport-Security' => [
                'alias' => 'HSTS',
                'description' => 'The Strict-Transport-Security response header (often abbreviated as HSTS) lets a web site tell browsers that it should only be accessed using HTTPS, instead of using HTTP.',
                'solution' => 'Add the following header to your web server configuration: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                'score' => 15,
                'passed' => !empty($headers['Strict-Transport-Security']),
            ],
            'X-Frame-Options' => [
                'alias' => 'XFO',
                'description' => 'The X-Frame-Options HTTP response header can be used to indicate whether or not a browser should be allowed to render a page in a frame or iframe.',
                'solution' => 'Add the following header to your web server configuration: X-Frame-Options: SAMEORIGIN',
                'score' => 15,
                'passed' => !empty($headers['X-Frame-Options']) && $headers['X-Frame-Options'] === 'SAMEORIGIN',
            ],
            'X-Content-Type-Options' => [
                'alias' => 'XCTO',
                'description' => 'The X-Content-Type-Options HTTP response header is a marker used by the server to indicate that the MIME types advertised in the Content-Type headers should not be changed and be followed.',
                'solution' => 'Add the following header to your web server configuration: X-Content-Type-Options: nosniff',
                'score' => 15,
                'passed' => !empty($headers['X-Content-Type-Options'])
            ],
            'Content-Security-Policy' => [
                'alias' => 'CSP',
                'description' => 'The Content-Security-Policy response header allows web site administrators to control resources the user agent is allowed to load for a given page.',
                'solution' => 'Set a Content-Security-Policy header with a strong policy.',
                'score' => 15,
                'passed' => !empty($headers['Content-Security-Policy'])
            ],
            'Referrer-Policy' => [
                'description' => 'The Referrer-Policy response header controls how much referrer information (sent via the Referer header) should be included with requests made.',
                'solution' => 'set a Referrer-Policy header with a strong policy.',
                'score' => 15,
                'passed' => !empty($headers['Referrer-Policy'])
            ],
            'Permissions-Policy' => [
                'description' => 'The Permissions-Policy response header allows a site to control which features and APIs can be used in the browser.',
                'solution' => 'Set a Permissions-Policy header with a strong policy.',
                'score' => 15,
                'passed' => !empty($headers['Permissions-Policy'])
            ],
            'X-XSS-Protection' => [
                'alias' => 'X-XSS',
                'description' => 'The X-XSS-Protection HTTP header is a basic protection against XSS attacks. It is enabled by default in most browsers.',
                'solution' => 'Add the following header to your web server configuration: X-XSS-Protection: 1; mode=block',
                'score' => 2,
                'passed' => !empty($headers['X-XSS-Protection']) && $headers['X-XSS-Protection'] === '1; mode=block',
            ],
            'Server' => [
                'description' => 'The Server response header contains information about the software used by the origin server to handle the request. This is often the software name and version number, but may also contain other information such as platform. It is primarily for use by clients to aid in debugging and other interoperability concerns.',
                'solution' => 'Remove the Server header from your web server configuration.',
                'score' => 1,
                'passed' => empty($headers['Server'])
            ],
            'X-Powered-By' => [
                'description' => 'The X-Powered-By header is a common way for servers to advertise the technology they are using. It is not a standard header and is not part of any specification.',
                'solution' => 'Remove the X-Powered-By header from your web server configuration.',
                'score' => 1,
                'passed' => empty($headers['X-Powered-By'])
            ],
            'Cross-Origin-Embedder-Policy' => [
                'alias' => 'COEP',
                'description' => 'The Cross-Origin-Embedder-Policy response header allows you to ensure that a document is loaded in a cross-origin isolated state. This is a security feature that prevents a document from loading any non-same-origin resources which don\'t explicitly grant the document permission to be loaded.',
                'solution' => 'Set a Cross-Origin-Embedder-Policy header with a strong policy.',
                'score' => 2,
                'passed' => !empty($headers['Cross-Origin-Embedder-Policy'])
            ],
            'Cross-Origin-Opener-Policy' => [
                'alias' => 'COOP',
                'description' => 'The Cross-Origin-Opener-Policy response header allows you to ensure that a document is loaded in a cross-origin isolated state. This is a security feature that prevents a document from interacting with any non-same-origin documents which don\'t explicitly grant the document permission to be interacted with.',
                'solution' => 'Set a Cross-Origin-Opener-Policy header with a strong policy.',
                'score' => 2,
                'passed' => !empty($headers['Cross-Origin-Opener-Policy'])
            ],
            'Cross-Origin-Resource-Policy' => [
                'alias' => 'CORP',
                'description' => 'The Cross-Origin-Resource-Policy response header allows you to ensure that a document is loaded in a cross-origin isolated state. This is a security feature that prevents a document from loading any non-same-origin resources which don\'t explicitly grant the document permission to be loaded.',
                'solution' => 'Set a Cross-Origin-Resource-Policy header with a strong policy.',
                'score' => 2,
                'passed' => !empty($headers['Cross-Origin-Resource-Policy'])
            ],
        ];

        $score = 0;

        $analysis = [
        ];

        foreach ($security_headers as $header => $data) {
            $analysis[] = [
                'name' => $header . (!empty($data['alias']) ? ' (' . $data['alias'] . ')' : ''),
                'description' => $data['description'],
                'solution' => $data['solution'],
                'passed' => $data['passed'],
            ];

            if ($data['passed']) {
                $score += $data['score'];
            }
        }

        $grade = array_keys($score_map)[count($score_map) - 1];
        foreach ($score_map as $score_grade => $score_threshold) {
            if ($score >= $score_threshold) {
                $grade = $score_grade;
                break;
            }
        }

        return [
            'grade' => $grade,
            'analysis' => $analysis,
        ];
    }
}