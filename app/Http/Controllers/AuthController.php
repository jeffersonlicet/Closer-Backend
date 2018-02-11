<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Http\Models\User;
use Validator;

class AuthController extends Controller
{

    public function mountSignin(Request $request)
    {
        //$input = $request->only(['identity']);
    }

    public function usernameValidation(Request $request)
    {
        $validator = self::validateUsername($request->input('username'));
        return response()->json(['status' => $validator->passes(), 'report' => (!$validator->passes() ? $validator->messages()->first() : '' )]);
    }

    public function emailValidation(Request $request)
    {
        $validator = self::validateEmail($request->input('email'));
        return response()->json(['status' => $validator->passes(), 'report' => (!$validator->passes() ? $validator->messages()->first() : '' )]);
    }

    public function signin(Request $request)
    {   
        try {

            $input = $request->only([
                'identity', 
                'password']);

            $validator = self::validateSignin($input);

            if(!$validator->passes())
                return response()->json(['status' => FALSE, 'report' => $validator->messages()->first()]);

            $sanitized = filter_var($input['identity'], FILTER_SANITIZE_EMAIL);

            if(!($user = User::where(($sanitized == $input['identity'] && filter_var($sanitized, FILTER_VALIDATE_EMAIL)) ? 'email' : 'username', $input['identity'])->first()))
                return response()->json(['status' => FALSE, 'report' => 'User not found']);
            
            $token = $this->generateToken($user->email, $input['password']);

            return response()->json(['status' => true, 'user' => $user, 'credentials' => $token]);
        }
        catch (\GuzzleHttp\Exception\ClientException $ex) {
            $body = json_decode($ex->getResponse()->getBody()->getContents());
            return response()->json(['status' => false, 'report' => $body->message]);
        }
        catch(\Exception $ex) {
            return response()->json(['status' => false, 'report' => $ex->getMessage()]);
        }
    }

    public function signup(Request $request)
    {
        $input = $request->only([
            'username',
            'email', 
            'password']);

        $validator = self::validateSignup($input);

        if ($validator->fails()) 
            return response()->json(['status' => false, 'report' => $validator->errors()->first()]);
        
        $user = User::create([
            'username' => $input['username'],
            'email' => $input['email'],
            'name' => '',
            'password' => bcrypt($input['password']),
        ]);

        $token  = $this->generateToken($input['email'], $input['password']);

        return response()->json(['status' => true, 'user' => $user, 'credentials' => $token]);       
    }

    private function generateToken(string $email, string $password)
    {
        $guzzle = new \GuzzleHttp\Client;
        
        $response = $guzzle->post(url('/oauth/token'), [
            'form_params' => [
                'grant_type' => 'password',
                'client_id' => '5',
                'client_secret' => 'mmp3XmL4KxJ5VgAwJfYIAWbJpAqv7lrB9hd83OgM',
                'username' => $email,
                'password' => $password,
                'scope' => '*',
            ],
        ]);
        
        return json_decode((string) $response->getBody(), true);
    }

    protected static function validateSignup(array $data)
    {
        return Validator::make($data, [
            'email' => 'required|string|email|max:255|unique:users',
            'username' => 'required|string|allowed_username|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);
    }

    protected static function validateSignin(array $data)
    {
        return Validator::make($data, [
            'identity' => 'required',
            'password' => 'required',
        ]);
    }

    protected static function validateUsername($username)
    {
        return Validator::make(['username' => $username], [
            'username' => 'required|string|allowed_username|max:255|unique:users'
        ]);
    }

    protected static function validateEmail($email)
    {
        return Validator::make(['email' => $email], [
            'email' => 'required|string|email|max:255|unique:users'
        ]);
    }
}
