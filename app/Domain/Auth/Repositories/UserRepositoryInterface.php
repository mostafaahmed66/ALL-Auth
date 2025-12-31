<?php

namespace App\Domain\Auth\Repositories;

interface UserRepositoryInterface
{
    public function create(array $data);
    public function findByPhone(string $phone);
    public function verifyPhone($user);
    public function findOrCreateFromGoogle(array $data);

}
