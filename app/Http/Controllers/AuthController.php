<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Http\Models\User;
use Validator;

class AuthController extends Controller
{
    public function signin(Request $request)
    {   
        try {

            $input = $request->only([
                'username', 
                'password']);

            $validator = $this->validateSignin($input);

            if(!$validator->passes())
                return response()->json(['status' => FALSE, 'report' => $validator->messages()->first()]);

            $sanitized = filter_var($input['username'], FILTER_SANITIZE_EMAIL);

            if(!($user = User::where(($sanitized == $input['username'] && filter_var($sanitized, FILTER_VALIDATE_EMAIL)) ? 'email' : 'username', $input['username'])->first()))
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
            'name', 
            'username',
            'email', 
            'password']);

        $validator = $this->validateSignup($input);

        if ($validator->fails()) 
            return response()->json(['status' => false, 'report' => $validator->errors()->first()]);
        
        $user = User::create([
            'name' => $input['name'],
            'username' => $input['username'],
            'email' => $input['email'],
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

    /**
     * Get a validator for an incoming registration request.
     *
     * @param  array  $data
     * @return \Illuminate\Contracts\Validation\Validator
     */
    protected function validateSignup(array $data)
    {
        return Validator::make($data, [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'username' => 'required|string|allowed_username|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);
    }

    /**
     * Get a validator for an incoming signin request.
     *
     * @param  array  $data
     * @return \Illuminate\Contracts\Validation\Validator
     */
    protected function validateSignin(array $data)
    {
        return Validator::make($data, [
            'username' => 'required',
            'password' => 'required',
        ]);
    }
}
