<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use App\Http\Controllers\ApiController;
use Illuminate\Support\Facades\Validator;

class AuthController extends ApiController
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(),[
            'name' => ['required','string'],
            'username' => ['required','string','unique:users,username'],
            'email' => ['required','email','unique:users,email'],
            'password' => ['required','string'],
            'c_password' => ['required','same:password'],

        ]);

        if($validator->fails())
        {
            return $this->errorResponse($validator->messages(),422);
        }

        $user = User::create([
            'name' => $request->name,
            'username' => $request->username,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

    $token = JWTAuth::fromUser($user);

    $refreshtoken = JWTAuth::claims(['type' => 'refresh'])->fromUser($user);

    $cookie = cookie(
        'refresh_token',
        $refreshtoken,
    );


        return $this->successResponse([
            'token' => $token,
            'user'=> $user
        ],201)->cookie($cookie);
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(),[
            'username' => ['required','string'],
            'password' => ['required','string']
        ]);

        if($validator->fails())
        {
            return $this->errorResponse($validator->messages(),422);
        }

        $user = User::where('username',$request->username)->first();
        if(!$user)
        {
            return $this->errorResponse('user not found',401);
        }

        if(!Hash::check($request->password,$user->password))
        {
            return $this->errorResponse('password is wrong',401);
        }
        
        $token = JWTAuth::fromUser($user);
        $refreshtoken = JWTAuth::claims(['type' => 'refresh'])->fromUser($user);

        $cookie = cookie(
            'refresh_token',
            $refreshtoken,
        );

        return $this->successResponse([
            'token' => $token,
            'user'=> $user
        ],200)->cookie($cookie);
    }

}