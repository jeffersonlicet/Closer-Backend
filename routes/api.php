<?php

use Illuminate\Http\Request;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

# The authenticated routes
Route::middleware('auth:api')->group(function () {

});

# The guest routes
Route::post('/signin', 'AuthController@signin');
Route::post('/signup', 'AuthController@signup');