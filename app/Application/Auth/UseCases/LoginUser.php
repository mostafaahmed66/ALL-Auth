<?php

namespace App\Application\Auth\UseCases;

use App\Domain\Auth\Repositories\UserRepositoryInterface;

class LoginUser
{
    /**
     * Create a new class instance.
     */
    public function __construct( private UserRepositoryInterface $userRepo)
    {
        //
    }

    public function execute(array $data)
    {
        $user=$this->userRepo->findByPhone($data['phone']);
        if(!$user || !password_verify($data['password'],$user->password)){
            throw new \Exception("Invalid credentials");
        }
        if(! $user->phone_verified_at) {
            throw new \Exception("Phone number not verified");
        }

        $token = auth()->login($user);

        return response()->json([
            'user' => $user,
            'token' => $token
        ], 200);

    }

}
