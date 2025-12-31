<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\SocialController;
Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');
Route::post('register', [AuthController::class, 'register']);
Route::post('login', [AuthController::class, 'login']);
Route::post('verify-otp', [AuthController::class, 'verifyOtp']);
Route::post('resend-otp', [AuthController::class, 'resendOtp']);



Route::get('google/redirect', [SocialController::class, 'redirectToGoogle']);
Route::get('google/callback', [SocialController::class, 'handleGoogleCallback']);

Route::middleware('auth:api')->group(function () {
    Route::post('logout', [AuthController::class, 'logout']);
    Route::get('me', [AuthController::class, 'me']);
    Route::post('forgot-password', [AuthController::class, 'forgotPassword']);
    Route::post('reset-password', [AuthController::class, 'resetPassword']);
    Route::delete('delete-account', [AuthController::class, 'deleteAccount']);
    Route::post('/change-phone/request', [AuthController::class, 'requestChangePhone']);
    Route::post('/change-phone/verify', [AuthController::class, 'verifyChangePhone']);
    Route::post('/change-password', [AuthController::class, 'changePassword']);
    Route::delete('/delete/account', [AuthController::class, 'deleteAccount']);




});
