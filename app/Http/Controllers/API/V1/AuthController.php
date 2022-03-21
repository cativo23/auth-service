<?php

namespace App\Http\Controllers\API\V1;

use App\Http\Requests\API\V1\Auth\LoginRequest;
use Illuminate\Http\JsonResponse;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Contracts\BaseAPIController
{
    /**
     * @throws ValidationException
     */
    public function login(LoginRequest $request): JsonResponse
    {
        if (! $token = $request->authenticate()) {
            return $this->errorUnauthorized();
        }

        return $this->setStatusCode(Response::HTTP_OK)->success(
            'Logged in successfully.',
            [
                'access_token' => $token,
                'token_type' => 'bearer',
                'expires_in' => auth()->factory()->getTTL() * 60
            ]
        );
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return $this->respondWithSuccess('Successfully logged out');
    }

    /**
     * Refresh a token.
     *
     * @return JsonResponse
     */
    public function refresh()
    {
        return $this->setStatusCode(Response::HTTP_OK)->success(
        'Logged in successfully.',
        [
            'access_token' => auth()->refresh(),
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]
    );
    }
}
