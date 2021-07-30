<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login','payload']]);
    }

    // 登入並回傳 jwt Token
    public function login()
    {
        $credentials = request(['email', 'password']);

        // TODO: 了解 guard 怎麼切換
        // 因為 guard 換成 jwt, attempt function 的位置在 Tymon\JWTAuth\JWTGuard;
        // 嘗試用 request 中的參數認證使用者
        if (!$token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        return $this->respondWithToken($token);
    }

    // 驗證 jwt token 回傳持有人
    public function verify()
    {
        // auth() 是 authManager， 在Illuminate\Auth\AuthManager
        return response()->json(['name'=>auth()->user()->name]);
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
        // iss   jwt 的發行方
        // iat   jwt 發行時間 issued at time
        // exp   過期時間 expiration time
        // nbf   (跟iat一樣?) 當前時間不能早於這個時間 not before time
        // jti   jwt id 確保唯一性
        // sub   識別訊息 subject ??
        // prv   User Provider 的 hash 結果  https://github.com/tymondesigns/jwt-auth/issues/1344

        $payload = auth()->payload();
        return response()->json($payload);
    }

    // 不太確定 validate 用法
    // public function jwtValidate()
    // {
    //     $credentials = request(['email', 'password']);
    //     return auth()->validate($credentials)==true ? auth()->validate($credentials) : response()->json(['message' => 'failed']);
    // }
}
