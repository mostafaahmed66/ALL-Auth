<?php

namespace App\Application\Auth\UseCases;

use App\Domain\Auth\Repositories\UserRepositoryInterface;
use App\Domain\Auth\Services\OtpService;

class RegisterUser
{
    public function __construct(
        private UserRepositoryInterface $userRepo,
        private OtpService $otpService
    ) {}

    public function execute(array $data)
    {
        $user = $this->userRepo->create([
            'name' => $data['name'],
            'phone' => $data['phone'],
            'password' => bcrypt($data['password']),
        ]);

        $otp = $this->otpService->generate($user->id);

        return [
            'user' => $user,
            'otp' => $otp // testing only
        ];
    }
}
