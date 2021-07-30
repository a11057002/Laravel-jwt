<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login']]);
    }

    // 登入並回傳 jwt Token
    public function login()
    {
        $credentials = request(['email', 'password']);

        // TODO: 了解 guard 怎麼切換
        // 因為 guard 換成 jwt, attempt function 的位置在 Tymon\JWTAuth\JWTGuard;
        if (!$token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    // 驗證 jwt token 回傳持有人
    public function me()
    {
        // auth() 是 authManager， 在Illuminate\Auth\AuthManager
        return response()->json(auth()->user());
    }

    // 銷毀傳進的 jwtToken
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    // 重新分配一個 jwt token
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    // 將 jwt token 塞入 response
    // factory 在 \Tymon\JwtAuth\Factory
    protected function respondWithToken($token)
    {
        dd(auth());
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }
}
