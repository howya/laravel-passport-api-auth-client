<?php
/**
 * Created by PhpStorm.
 * User: rbennett
 * Date: 06/05/2018
 * Time: 11:39
 */

namespace RBennett\AbstractAPIAuthClient;


use RBennett\AbstractAPIAuthClient\Contracts\HTTPRequestContract;
use GuzzleHttp\Client;

class GuzzleAdapter implements HTTPRequestContract
{
    /**
     * @var Client
     */
    private $http;

    /**
     * GuzzleAdapter constructor.
     * @param Client $http
     */
    public function __construct(Client $http)
    {
        $this->http = $http;
    }

    /**
     * @param string $verb
     * @param string $uri
     * @param array $headers
     * @param array $query
     * @param array $formParams
     * @return array
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function request(string $verb, string $uri, array $headers = [], array $query = [], array $formParams = []): array
    {
        $requestArray = [
            'query' => $query,
            'headers' => $headers,
            'form_params' => $formParams,
            'http_errors' => false
        ];


        $response = $this->http->request($verb, $uri, $requestArray);

        return [
            'headers' => $response->getHeaders(),
            'body' => json_decode($response->getBody(), true),
            'statusCode' => $response->getStatusCode()
        ];

    }


}