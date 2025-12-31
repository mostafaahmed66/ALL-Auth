<?php

namespace App\Application\Auth\UseCases;

use Exception;
use App\Domain\Auth\Services\OtpService;
use App\Domain\Auth\Repositories\UserRepositoryInterface;

class VerifyOtp
{
    /**
     * Create a new class instance.
     */
    public function __construct(
       private UserRepositoryInterface $userRepo,
         private OtpService $otpService

    )
    {
        //
    }

    public function execute(array $data)
    {
        $user=$this->userRepo->findByPhone($data['phone']);
        if(!$user){
            throw new Exception("User not found");
        }

        $isvalid=$this->otpService->verify($user->id,$data['otp']);
        if(!$isvalid){
            throw new Exception("Invalid OTP");
        }


        $this->userRepo->verifyphone($user);
        $token = auth()->login($user);
        return response()->json([
            'message' => 'Phone verified successfully',
            'access_token' => $token,
            'token_type' => 'Bearer',
            'user' => $user
        ]);
    }


}
