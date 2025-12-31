<?php

namespace App\Domain\Auth\Services;

use Laravel\Socialite\Facades\Socialite;

class GoogleAuthService
{
    /**
     * Create a new class instance.
     */
  public function redirect()
    {
        return Socialite::driver('google')
            ->stateless()
            ->redirect();
    }

    public function getUser()
    {
        $user = Socialite::driver('google')
            ->stateless()
            ->user();

        return [
            'name'  => $user->getName(),
            'email' => $user->getEmail(),
        ];
    }
}
