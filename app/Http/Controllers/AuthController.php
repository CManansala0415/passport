<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Auth;
use Carbon\Carbon;
class AuthController extends Controller
{
    public function register(Request $request){
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email',
            'password' => 'required|string|confirmed',
        ]);

        $user = new User();
        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = app('hash')->make($request->password);

        if($user->save()){
            return response()->json([
                'message' => 'User Created Successfully',
                'status' => '201',
            ],201);
        }

        else{
            return response()->json([
                'message' => 'Error occured',
                'status' => '500',
            ],500);
        }
    }

    public function login(Request $request){
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
            'remember_me' => 'boolean'
        ]);

        if(!Auth::attempt(['email' => $request->email, 'password' => $request->password])){
            return response()->json([
                'message' => 'Unauthorized',
                'status' => '401',
            ],401);
        }

        $user = $request->user();

        if($user->role == 'administrator'){
            $tokenData = $user->createToken('Personal Access Token', ['*']);
        }
        else{
            $tokenData = $user->createToken('Personal Access Token', ['create','update','delete']);
        }
        
        if($request->remember_me){
            $tokenData->expires_at = Carbon::now()->addWeeks(1);
        }
        $token = $tokenData->plainTextToken;
        return $tokenData;  

        // if($request->remember_me){
        //     $tokenData->expires_at = Carbon::now()->addWeeks(1);
        // }

        // if($token->save()){
        //     return response()->json([
        //         'user' => $user,
        //         'access_token' => $tokenData->accessToken,
        //         'token_type' => 'Bearer',
        //         'token_scope' => $tokenData->plainTextToken->scopes[0],
        //         'expires_at' => Carbon::parse($tokenData->plainTextToken->expires_at)->toDateTimeString(),
        //         'status' => 200,
        //     ],200);
        // }
        // else{
        //     return response()->json([
        //         'message' => 'Error nanaman',
        //         'status' => 500,
        //     ],500);
        // }
    }

    public function logout(Request $request){
        $request->user()->token()->revoke();
        return response()->json([
            'message' => 'Logged out',
            'status' => 200,
        ],200);
    }
}
