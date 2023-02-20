<?php

namespace eru123\webtools;

use Exception;

class Helper
{

    /**
     * Get the request body
     * @return array Either the JSON body or the POST body (if JSON is not present)
     */
    final public static function request_body(): array
    {
        $body = [];
        if (@$_SERVER['CONTENT_TYPE'] === 'application/json') {
            $body = json_decode(file_get_contents('php://input'), true);
        } else {
            $body = $_POST;
        }
        return $body;
    }

    final public static function schema_validator(array $data, array $schema)
    {
        $accepted_properties = ['type', 'required', 'default', 'alias', 'min', 'max', 'regex', 'values'];
        $accepted_types = ['string', 'int', 'float', 'bool', 'array', 'enum', 'json', 'email'];

        foreach ($schema as $key => $opts) {
            if (is_string($opts) && in_array($opts, $accepted_types)) {
                $schema[$key] = ['type' => $opts];
            } else if (is_string($opts) && !in_array($opts, $accepted_types)) {
                throw new Exception("Invalid type: $opts", 500);
            }
            foreach ($opts as $prop => $val) {
                if (!in_array($prop, $accepted_properties)) {
                    throw new Exception("Invalid property: $prop", 500);
                }
            }
        }

        $default = [
            'type' => 'string',
            'required' => false,
            'default' => null,
        ];

        $result = [];

        foreach ($schema as $key => $opts) {
            $alias = @$opts['alias'] ?? $key;

            if (is_string($opts) || empty($opts)) {
                $opts = ['type' => $opts];
            }

            $opts = array_merge($default, $opts);

            if ($opts['required'] && !isset($data[$key])) {
                throw new Exception("Missing required field: $alias", 400);
            } else if (!$opts['required'] && !isset($data[$key])) {
                $data[$key] = $opts['default'];
            }

            $opts['type'] = strtolower($opts['type']);
            if ($opts['type'] === 'string' || $opts['type'] === 'email') {
                $data[$key] = (string) $data[$key];
            } else if ($opts['type'] === 'int') {
                $data[$key] = (int) $data[$key];
            } else if ($opts['type'] === 'float') {
                $data[$key] = (float) $data[$key];
            } else if ($opts['type'] === 'bool') {
                $data[$key] = (bool) $data[$key];
            } else if ($opts['type'] === 'array') {
                $data[$key] = (array) $data[$key];
            } else if ($opts['type'] === 'object') {
                $data[$key] = (object) $data[$key];
            } else if ($opts['type'] === 'json') {
                $data[$key] = json_decode($data[$key], true);
            } else if ($opts['type'] === 'enum') {
                $data[$key] = is_numeric($data[$key]) ? (int) $data[$key] : (string) $data[$key];
            }

            if ($opts['type'] === 'string' && isset($opts['min']) && strlen($data[$key]) < $opts['min']) {
                throw new Exception("Field $alias must be at least {$opts['min']} characters long", 400);
            }

            if ($opts['type'] === 'string' && isset($opts['max']) && strlen($data[$key]) > $opts['max']) {
                throw new Exception("Field $alias must be at most {$opts['max']} characters long", 400);
            }

            if ($opts['type'] === 'string' && isset($opts['regex']) && !preg_match($opts['regex'], $data[$key])) {
                throw new Exception("Field $alias must match the regex {$opts['regex']}", 400);
            }

            if ($opts['type'] === 'email' && !filter_var($data[$key], FILTER_VALIDATE_EMAIL)) {
                throw new Exception("Field $alias must be a valid email address", 400);
            }

            if (($opts['type'] === 'int' || $opts['type'] === 'float') && isset($opts['min']) && $data[$key] < $opts['min']) {
                throw new Exception("Field $alias must be at least {$opts['min']}", 400);
            }

            if (($opts['type'] === 'int' || $opts['type'] === 'float') && isset($opts['max']) && $data[$key] > $opts['max']) {
                throw new Exception("Field $alias must be at most {$opts['max']}", 400);
            }

            if ($opts['type'] === 'array' && isset($opts['min']) && count($data[$key]) < $opts['min']) {
                throw new Exception("Field $alias must have at least {$opts['min']} items", 400);
            }

            if ($opts['type'] === 'array' && isset($opts['max']) && count($data[$key]) > $opts['max']) {
                throw new Exception("Field $alias must have at most {$opts['max']} items", 400);
            }

            if ($opts['type'] === 'enum' && isset($opts['values']) && (!is_array(@$opts['values']) || empty($opts['values']))) {
                throw new Exception("Field $alias must have a non-empty array of values", 400);
            }

            if ($opts['type'] === 'enum' && isset($opts['values']) && !in_array($data[$key], (array) $opts['values'])) {
                throw new Exception("Field $alias must be one of: " . implode(', ', $opts['values']), 400);
            }

            $result[$key] = $data[$key];
        }

        return $result;
    }
}