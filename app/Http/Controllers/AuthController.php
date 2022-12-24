<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $user = User::create([
            "name" => $request->name,
            "email" => $request->email,
            "password" => Hash::make($request->password)
        ]);

        $credential = $request->only("email", "password");
        $token = JWTAuth::attempt($credential);

        return response()->json([
            "status" => "success",
            "message" => "success register",
            "token" => $token
        ]);
    }

    public function login(Request $request)
    {
        $credential = $request->only('email', 'password');
        $token = JWTAuth::attempt($credential);

        if (!$token) {
            return response()->json([
                "status" => "error",
                "message" => 'Unauthorized'
            ], 401);
        }

        $user = Auth::user();

        return response()->json([
            'status' => "success",
            'user' => $user,
            'authorisation' => [
                'token' => $token,
                'type' => 'bearer'
            ]
        ]);
    }
}