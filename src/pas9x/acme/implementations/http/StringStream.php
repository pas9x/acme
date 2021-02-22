<?php

namespace pas9x\acme\implementations\http;

use RuntimeException;
use Psr\Http\Message\StreamInterface;

class StringStream implements StreamInterface
{
    protected $stream;
    protected $size;
    protected $closed = false;

    public function __construct(string $string)
    {
        $this->stream = fopen('php://memory', 'r+');
        fwrite($this->stream, $string);
        rewind($this->stream);
        $this->size = strlen($string);
    }

    public function __toString()
    {
        if ($this->closed) {
            return '';
        }
        try {
            return $this->getContents();
        } catch (\Throwable $e) {
            return '';
        }
    }

    public function close()
    {
        if (!$this->closed) {
            fclose($this->stream);
            $this->stream = null;
            $this->closed = true;
        }
    }

    public function detach()
    {
        if ($this->closed) {
            return null;
        } else {
            $result = $this->stream;
            $this->closed = true;
            $this->stream = null;
            return $result;
        }
    }

    public function getSize()
    {
        return $this->closed ? null : $this->size;
    }

    public function tell()
    {
        $this->checkClosed();
        $result = ftell($this->stream);
        if (is_int($result)) {
            return $result;
        } else {
            throw new RuntimeException('ftell() failed');
        }
    }

    public function eof()
    {
        return $this->closed ? true : feof($this->stream);
    }
    
    public function isSeekable()
    {
        return true;
    }

    public function seek($offset, $whence = SEEK_SET)
    {
        $this->checkClosed();
        $ok = fseek($this->stream, $offset, $whence);
        if ($ok !== 0) {
            throw new RuntimeException('fseek() failed, result=' . $ok);
        }
    }
    
    public function rewind()
    {
        $this->checkClosed();
        $ok = rewind($this->stream);
        if ($ok !== true) {
            throw new RuntimeException('rewind() failed. result=' . $ok);
        }
    }

    public function isWritable()
    {
        return true;
    }

    public function write($string)
    {
        $this->checkClosed();
        $bytesWritten = fwrite($this->stream, $string);
        if (is_int($bytesWritten)) {
            $dataLength = strlen($string);
            if ($bytesWritten !== $dataLength) {
                throw new RuntimeException("fwrite() failed. dataLength=$dataLength, bytesWritten=$bytesWritten");
            }
        } else {
            throw new RuntimeException('fwrite() failed');
        }
    }

    public function isReadable()
    {
        return true;
    }

    public function read($length)
    {
        $this->checkClosed();
        $result = fread($this->stream, $length);
        if (is_string($result)) {
            return $result;
        } else {
            throw new RuntimeException('fread() failed');
        }
    }

    public function getContents()
    {
        $this->checkClosed();
        return stream_get_contents($this->stream);
    }

    public function getMetadata($key = null)
    {
        if (!$this->closed) {
            $metadata = stream_get_meta_data($this->stream);
            if (is_array($metadata)) {
                if ($key === null) {
                    return $metadata;
                } elseif (array_key_exists($key, $metadata)) {
                    return  $metadata[$key];
                }
            }
        }
        return null;
    }
    
    protected function checkClosed()
    {
        if ($this->closed) {
            throw new RuntimeException('This StringStream is closed');
        }
    }
}