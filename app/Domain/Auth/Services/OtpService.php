<?php

namespace App\Domain\Auth\Services;

use Exception;
use App\Models\Otp;
use Illuminate\Support\Facades\Hash;

class OtpService
{
    public function generate($userId)
    {
        $code = rand(100000, 999999);

        Otp::create([
            'user_id' => $userId,
            'code' => bcrypt($code),
            'expires_at' => now()->addMinutes(5)
        ]);

        return $code;
    }

    public function verify($userId, $code)
    {
        $otp = Otp::where('user_id', $userId)
            ->where('expires_at', '>', now())
            ->latest()
            ->first();

        if (!$otp || !Hash::check($code, $otp->code)) {
            throw new Exception("Invalid or expired OTP");
        }

        return true;
    }
}
