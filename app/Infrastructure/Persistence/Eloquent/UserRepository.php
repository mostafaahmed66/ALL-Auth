<?php

namespace App\Infrastructure\Persistence\Eloquent;

use App\Domain\Auth\Repositories\UserRepositoryInterface;
use App\Models\User;

class UserRepository implements UserRepositoryInterface
{
    public function create(array $data)
    {
        return User::create($data);
    }

    public function findByPhone(string $phone)
    {
        return User::where('phone', $phone)->firstOrFail();
    }

    public function verifyPhone($user)
    {
        $user->update([
            'phone_verified_at' => now()
        ]);
    }
    public function findOrCreateFromGoogle(array $data): User
    {
        return User::firstOrCreate(
            ['email' => $data['email']],
            [
                'name'              => $data['name'],
                'password'          => bcrypt(uniqid()),
                'email_verified_at' => now(),
                'phone_verified_at' => now(),
            ]
        );
    }
}
