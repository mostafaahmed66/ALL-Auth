<?php

namespace App\Application\Auth\UseCases;

use App\Domain\Auth\Services\GoogleAuthService;
use App\Infrastructure\Persistence\Eloquent\UserRepository;

class GoogleLogin
{
    public function __construct(
        private GoogleAuthService $googleService,
        private UserRepository $userRepository
    ) {}

    public function execute(): array
    {
        // 1️⃣ Get data from Google
        $googleUser = $this->googleService->getUser();

        // 2️⃣ Find or create user
        $user = $this->userRepository
            ->findOrCreateFromGoogle($googleUser);

        // 3️⃣ Generate token
        $token = auth()->login($user);

        // 4️⃣ Response
        return [
            'access_token' => $token,
            'token_type'   => 'Bearer',
            'user' => [
                'id'    => $user->id,
                'name'  => $user->name,
                'email' => $user->email,
            ],
        ];
    }
}
