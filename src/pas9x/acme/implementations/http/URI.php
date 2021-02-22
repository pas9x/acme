<?php

namespace pas9x\acme\implementations\http;

use Psr\Http\Message\UriInterface;

class URI extends Cloneable implements UriInterface
{
    protected $scheme;
    protected $host;
    protected $port;
    protected $user;
    protected $pass;
    protected $path;
    protected $query;
    protected $fragment;

    public function __construct(string $url)
    {
        $parts = parse_url($url);
        $this->scheme = $parts['scheme'] ?? '';
        $this->host = $parts['host'] ?? '';
        $this->port = isset($parts['port']) ? intval($parts['port']) : 0;
        $this->user = $parts['user'] ?? '';
        $this->pass = $parts['pass'] ?? '';
        $this->path = $parts['path'] ?? '';
        $this->query = $parts['query'] ?? '';
        $this->fragment = $parts['fragment'] ?? '';
    }

    public function getScheme()
    {
        return $this->scheme;
    }

    public function getAuthority()
    {
        if ($this->host === '') {
            return '';
        }
        $result = '';
        if ($this->user !== '') {
            $result .= rawurlencode($this->user);
            if ($this->pass !== '') {
                $result .= ':' . rawurlencode($this->pass);
            }
            $result .= '@';
        }
        $result .= $this->host;
        if ($this->scheme === 'http') {
            if ($this->port !== 0 && $this->port !== 80) {
                $result .= ':' . $this->port;
            }
        } elseif ($this->scheme === 'https') {
            if ($this->port !== 0 && $this->port !== 443) {
                $result .= ':' . $this->port;
            }
        } else {
            if ($this->port !== 0) {
                $result .= ':' . $this->port;
            }
        }
        return $result;
    }

    public function getUserInfo()
    {
        if ($this->user === '') {
            return '';
        }
        $result = $this->user;
        if ($this->pass !== '') {
            $result .= ':' . $this->pass;
        }
        return $result;
    }

    public function getHost()
    {
        return $this->host;
    }

    public function getPort()
    {
        return ($this->port > 0 && $this->port < 65536) ? $this->port : null;
    }

    public function getPath()
    {
        return $this->path;
    }

    public function getQuery()
    {
        return $this->query;
    }

    public function getFragment()
    {
        return $this->fragment;
    }

    public function withScheme($scheme)
    {
        return $this->withOne('scheme', $scheme);
    }

    public function withUserInfo($user, $password = null)
    {
        $properties = [
            'user' => $user,
            'pass' => $password,
        ];
        return $this->withMany($properties);
    }

    public function withHost($host)
    {
        return $this->withOne('host', $host);
    }

    public function withPort($port)
    {
        return $this->withOne('port', $port);
    }

    public function withPath($path)
    {
        return $this->withOne('path', $path);
    }

    public function withQuery($query)
    {
        return $this->withOne('query', $query);
    }

    public function withFragment($fragment)
    {
        return $this->withOne('fragment', $fragment);
    }

    public function __toString()
    {
        $result = '';
        if ($this->scheme !== '') {
            $result .= $this->scheme . '://';
        }
        $result .= $this->getAuthority();
        $result .= ($this->path === '') ? '/' : $this->path;
        if ($this->query !== '') {
            $result .= '?' . $this->query;
        }
        if ($this->fragment !== '') {
            $result .= '#' . $this->fragment;
        }
        return $result;
    }
}