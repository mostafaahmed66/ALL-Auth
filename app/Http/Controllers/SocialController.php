<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Laravel\Socialite\Facades\Socialite;
use App\Application\Auth\UseCases\GoogleLogin;
use App\Domain\Auth\Services\GoogleAuthService;

class SocialController extends Controller
{
    public function redirectToGoogle(GoogleAuthService $googleAuthService ) {
        return $googleAuthService->redirect();
    }

   public function handleGoogleCallback(GoogleLogin $useCase){
    return $useCase->execute();
   }
}
