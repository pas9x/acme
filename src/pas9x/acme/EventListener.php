<?php

namespace pas9x\acme;

use pas9x\acme\dto\Event;

interface EventListener
{
    public function onEvent(Event $event);
}