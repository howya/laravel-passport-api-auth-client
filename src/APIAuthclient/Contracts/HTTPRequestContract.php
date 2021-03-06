<?php

namespace RBennett\AbstractAPIAuthClient\Contracts;


interface HTTPRequestContract
{
    public function request(string $verb, string $uri, array $headers, array $query, array $formParams): array;
}