<?php

namespace RBennett\AbstractAPIAuthClient;

use RBennett\AbstractAPIAuthClient\Contracts\APIAuthclientContract;
use RBennett\AbstractAPIAuthClient\Contracts\HTTPRequestContract;
use RBennett\AbstractRepository\AbstractRepository;
use RBennett\AbstractRepository\Criteria\GenericAndWhere;
use Illuminate\Http\Request;

class APIAuthclient implements APIAuthclientContract
{
    /**
     * @var AbstractRepository
     */
    private $userIntegrations;

    /**
     * @var AbstractRepository
     */
    private $integrationServers;

    /**
     * @var HTTPRequestContract
     */
    private $httpRequest;

    /**
     * APIAuthclient constructor.
     * @param AbstractRepository $userIntegrations
     * @param AbstractRepository $integrationServers
     * @param HTTPRequestContract $httpAdapter
     */
    public function __construct(
        AbstractRepository $userIntegrations,
        AbstractRepository $integrationServers,
        HTTPRequestContract $httpAdapter
    ) {
        $this->userIntegrations = $userIntegrations;
        $this->integrationServers = $integrationServers;
        $this->httpRequest = $httpAdapter;
    }

    /**
     * @param Request $request
     * @param int $requestedIntegrationServerID
     * @param string $scope
     * @return mixed
     */
    public function requestAuthCode(Request $request, int $requestedIntegrationServerID, string $scope)
    {
        $integrationServer = $this->integrationServers->findOrFail($requestedIntegrationServerID);

        $request->session()->put([
            'RequestedIntegrationServerID' => $requestedIntegrationServerID,
            'RequestedIntegrationServerScope' => $scope
        ]);

        $query = http_build_query([
            'client_id' => $integrationServer->client_id,
            'redirect_uri' => $integrationServer->redirect_uri,
            'response_type' => 'code',
            'scope' => $scope,
        ]);

        return redirect($integrationServer->authorize_uri . '?' . $query);
    }

    /**
     * @param Request $request
     * @param AbstractRepository $userIntegrations
     * @param int $userID
     * @param int $integrationServerID
     * @return mixed
     * @throws \App\Http\APIAuthclient\AuthClientException
     */
    public function processAuthCodeCallback(Request $request, int $userID)
    {
        $integrationServerID = $request->session()->get('RequestedIntegrationServerID');
        $integrationServerScope = $request->session()->get('RequestedIntegrationServerScope');

        if ($request->has('code') && $integrationServerID) {
            return $this->getAccessToken($userID, $integrationServerID, $request->input('code'), $integrationServerScope);
        } else {
            throw new AuthClientException("Invalid Authorization request response from API server for server ID $integrationServerID", 500);
        }
    }

    /**
     * @param Request $request
     * @param int $integrationServerID
     * @param int $userID
     * @return mixed
     */
    public function deleteIntegration(Request $request, int $integrationServerID, int $userID)
    {
        if($toDelete = $this->getUserIntegration($integrationServerID, $userID)){
            return $toDelete->delete();
        } else {
            return false;
        }
    }

    /**
     * @param string $verb
     * @param string $uri
     * @param int $integrationServerID
     * @param int $userID
     * @param array $headers
     * @param array $query
     * @param array $formParams
     * @return mixed
     * @throws AuthClientException
     */
    public function apiRequest(
        string $verb,
        string $uri,
        int $integrationServerID,
        int $userID,
        array $headers = [],
        array $query = [],
        array $formParams = [])
    {
        if($userIntegration = $this->getUserIntegration($integrationServerID, $userID)){

            $mergeheaders = array_merge(
                [
                    'Content-Type'  => 'application/json',
                    'Accept'        => 'application/json',
                    'Authorization' => 'Bearer ' . $userIntegration->access_token
                ],
                $headers
            );

            return $this->processApiRequestResponse($this->httpRequest->request($verb, $uri, $mergeheaders, $query, $formParams), $integrationServerID, $userID, func_get_args());

        } else {
            throw new AuthClientException("User integration server not found for integrationServerID $integrationServerID, userID $userID", 500);
        }
    }

    /**
     * @param int $userID
     * @param int $integrationServerID
     * @param string $authCode
     * @param $integrationServerScope
     * @return mixed
     * @throws AuthClientException
     */
    private function getAccessToken(int $userID, int $integrationServerID, string $authCode, $integrationServerScope)
    {
        $integrationServer = $this->integrationServers->findOrFail($integrationServerID);

        $formParams = [
            'grant_type' => 'authorization_code',
            'client_id' => $integrationServer->client_id,
            'client_secret' => $integrationServer->client_secret,
            'redirect_uri' => $integrationServer->redirect_uri,
            'code' => $authCode
        ];

        $decodedResponse = $this->httpRequest->request('POST', $integrationServer->token_uri, [], [], $formParams);

        if ($decodedResponse['statusCode'] == 200 &&
            $this->array_keys_exists(['token_type', 'expires_in', 'access_token', 'refresh_token'],
                $body = $decodedResponse['body'])) {

            return $this->createUserIntegration(
                $userID,
                $integrationServerID,
                $body['expires_in'],
                $body['refresh_token'],
                $body['access_token'],
                $body['token_type'],
                $integrationServerScope
            );

        } else {
            throw new AuthClientException("Invalid Authorization request response from API server for server ID $integrationServerID", 500);
        }
    }



    /**
     * @param array $arrayResponse
     * @param $userIntegration
     * @param $apiRequestArgs
     * @return array
     * @throws AuthClientException
     */
    private function processApiRequestResponse(array $arrayResponse, $integrationServerID, $userID, $apiRequestArgs)
    {
        if (array_key_exists('statusCode', $arrayResponse)){

            $statusCode = $arrayResponse['statusCode'];

            switch ($statusCode) {
                case 200:
                    return $arrayResponse;
                    break;
                case 401:
                    if($this->refreshAccessToken($integrationServerID, $userID, null)) {
                        return call_user_func_array([$this,'apiRequest'], $apiRequestArgs);
                    } else {
                        throw new AuthClientException("API request failed to update access token record", 500);
                    }
                    break;
                default:
                    throw new AuthClientException("API request returned unexpected response: " . print_r($arrayResponse, true), 500);
            }

        }
    }

    /**
     * @param $integrationServerID
     * @param $userID
     * @param null $scope
     * @param boolean $forceRefresh
     * @return mixed
     * @throws AuthClientException
     */
    public function refreshAccessToken($integrationServerID, $userID, $scope = null)
    {
        if (($userIntegration = $this->getUserIntegration($integrationServerID, $userID)) &&
            ($integrationServer = $this->getIntegrationServer($integrationServerID))) {

            $scopeToRequest = $scope ?? $userIntegration->scope;

            $formParams = [
                'grant_type' => 'refresh_token',
                'client_id' => $integrationServer->client_id,
                'client_secret' => $integrationServer->client_secret,
                'refresh_token' => $userIntegration->refresh_token,
                'scope' => $scopeToRequest
            ];

            $decodedResponse = $this->httpRequest->request('POST', $integrationServer->token_uri, [], [],
                $formParams);

            if($decodedResponse['statusCode'] == 200 &&
                $this->array_keys_exists(['token_type', 'expires_in', 'access_token', 'refresh_token'],
                    $body = $decodedResponse['body'])) {

                return $this->updateUserIntegration(
                    $userIntegration->id,
                    $body['expires_in'],
                    $body['refresh_token'],
                    $body['access_token'],
                    $body['token_type'],
                    $scopeToRequest
                );

            } else if($decodedResponse['statusCode'] == 401){
                throw new AuthClientException("API Token Refresh request failed as refresh token has expired", 401);
            } else {
                throw new AuthClientException("API Token Refresh request returned unexpected response: " . print_r($decodedResponse, true), 500);
            }

        } else {
            throw new AuthClientException("Unable to find integration server or user integration for integration server ID $integrationServerID and user ID $userID", 500);
        }

    }


    /**
     * @param int $integrationServerID
     * @param int $userID
     * @return mixed
     */
    private function getUserIntegration(int $integrationServerID, int $userID)
    {
        $models = $this->userIntegrations->getByCriteria(new GenericAndWhere([
            'integration_server_id' => $integrationServerID,
            'user_id' => $userID
        ]))->all();

        return $models->count() == 1 ? $models->first() : false;
    }

    /**
     * @param int $integrationServerID
     * @return mixed
     */
    private function getIntegrationServer(int $integrationServerID)
    {
        return $this->integrationServers->findOrFail($integrationServerID);
    }

    /**
     * @param int $id
     * @param int $expiresIn
     * @param string $refreshToken
     * @param string $accessToken
     * @param string $tokenType
     * @param string $scope
     * @return mixed
     */
    private function updateUserIntegration(
        int $id,
        int $expiresIn,
        string $refreshToken,
        string $accessToken,
        string $tokenType,
        string $scope)
    {
        return $this->userIntegrations->update([
            'access_token_expires_in' => $expiresIn,
            'refresh_token' => $refreshToken,
            'access_token' => $accessToken,
            'token_type' => $tokenType,
            'scope' => $scope
        ], $id);
    }

    /**
     * @param int $userID
     * @param int $integrationServerID
     * @param int $expiresIn
     * @param string $refreshToken
     * @param string $accessToken
     * @param string $tokenType
     * @param string $scope
     * @return mixed
     */
    private function createUserIntegration(
        int $userID,
        int $integrationServerID,
        int $expiresIn,
        string $refreshToken,
        string $accessToken,
        string $tokenType,
        string $scope)
    {
        return $this->userIntegrations->create([
            'user_id' => $userID,
            'integration_server_id' => $integrationServerID,
            'access_token_expires_in' => $expiresIn,
            'refresh_token' => $refreshToken,
            'access_token' => $accessToken,
            'token_type' => $tokenType,
            'scope' => $scope
        ]);
    }


    /**
     * @param array $keys
     * @param array $arr
     * @return bool
     */
    private function array_keys_exists(array $keys, array $arr)
    {
        return !array_diff_key(array_flip($keys), $arr);
    }


}