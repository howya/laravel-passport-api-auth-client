<?php

namespace RBennett\AbstractAPIAuthClient\Contracts;

use Illuminate\Http\Request;

interface APIAuthclientContract
{
    public function requestAuthCode(Request $request, int $requestedIntegrationServerID, string $scope);

    public function processAuthCodeCallback(Request $request, int $userID);

    public function deleteIntegration(Request $request, int $integrationServerID, int $userID);

    public function apiRequest(string $verb, string $uri, int $integrationServerID, int $userID, array $headers = [], array $query = [], array $form_params = []);

    public function refreshAccessToken($integrationServerID, $userID, $scope = null);
}