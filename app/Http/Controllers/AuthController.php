<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth', ['except' => ['login', 'payload']]);
    }

    // 登入並回傳 jwt Token
    public function login()
    {
        $credentials = request(['email', 'password']);

        // TODO: 了解 guard 怎麼切換
        // 因為 guard 換成 jwt, attempt function 的位置在 Tymon\JWTAuth\JWTGuard;
        // 嘗試用 request 中的參數認證使用者
        if (!$token = auth()->claims(['test' => '123444'])->attempt($credentials)) {
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
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }


    public function payload()
    {
        $payload = auth()->payload();
        return response()->json($payload);
    }

    // 提供帳密 和 jwt 做驗證
    public function jwtValidate()
    {
        $credentials = request(['email', 'password']);
        return auth()->validate($credentials)==true ? auth()->validate($credentials) : response()->json(['message' => 'failed']);
    }
}
