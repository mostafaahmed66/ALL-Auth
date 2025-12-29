<?php

namespace App\Http\Controllers;

use App\Models\Otp;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Cache;
use Carbon\Carbon;

class AuthController extends Controller
{
    // ========================= Register + OTP =========================
    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'phone' => 'required|unique:users,phone',
            'email' => 'nullable|email|unique:users,email',
            'password' => 'required|min:6',
        ]);

        $user = User::create([
            'name' => $request->name,
            'phone' => $request->phone,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);

        // generate OTP
        $otpCode = rand(100000, 999999);

        Otp::create([
            'user_id' => $user->id,
            'code' => bcrypt($otpCode),
            'expires_at' => now()->addMinutes(5),
        ]);

        // TODO: send SMS here
        // SMS::send($user->phone, $otpCode);

        return response()->json([
            'message' => 'OTP sent to your phone',
            'otp_for_testing' => $otpCode // امسحها في production
        ]);


    }

    // ========================= Verify OTP =========================
    public function verifyOtp(Request $request)
    {
        $request->validate([
            'phone' => 'required',
            'otp' => 'required'
        ]);

        $user = User::where('phone', $request->phone)->first();
        if (! $user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        $otp = Otp::where('user_id', $user->id)->latest()->first();
        if (! $otp) {
            return response()->json(['message' => 'OTP not found'], 404);
        }

        if (Carbon::parse($otp->expires_at)->isPast()) {
            return response()->json(['message' => 'OTP expired'], 422);
        }

        if (! Hash::check($request->otp, $otp->code)) {
            return response()->json(['message' => 'Invalid OTP'], 422);
        }

        // verify phone
        $user->phone_verified_at = now();
        $user->save();

        // delete otp
        $otp->delete();

        // generate token
        $token = auth()->login($user);

        return response()->json([
            'message' => 'Phone verified successfully',
            'access_token' => $token,
            'token_type' => 'Bearer',
            'user' => $user
        ]);
    }



    // ========================= Login =========================
    public function login(Request $request)
    {
        $credentials = $request->validate([
            'phone' => 'required',
            'password' => 'required',
        ]);

        $user = User::where('phone', $credentials['phone'])->first();
        if (! $user) {
            return response()->json(['message' => 'Invalid phone or password'], 401);
        }

        if (! $user->phone_verified_at) {
            return response()->json(['message' => 'Phone number not verified'], 403);
        }

        if (! $token = auth()->attempt($credentials)) {
            return response()->json(['message' => 'Invalid phone or password'], 401);
        }

        return response()->json([
            'access_token' => $token,
            'token_type' => 'Bearer',
            'user' => auth()->user(),
        ]);
    }

    // ========================= Resend OTP + Rate Limit =========================
    public function resendOtp(Request $request)
    {
        $request->validate(['phone' => 'required']);

        $user = User::where('phone', $request->phone)->first();
        if (! $user) {
            return response()->json(['message' => 'Phone not registered'], 404);
        }

        $cacheKey = 'otp_resend_' . $user->id;
        if (Cache::has($cacheKey)) {
            return response()->json(['message' => 'Please wait before requesting another OTP'], 429);
        }

        // delete old OTPs
        Otp::where('user_id', $user->id)->delete();

        $otpCode = rand(100000, 999999);

        Otp::create([
            'user_id' => $user->id,
            'code' => bcrypt($otpCode),
            'expires_at' => now()->addMinutes(2)
        ]);

        // TODO: send SMS
        // SMS::send($user->phone, $otpCode);

        Cache::put($cacheKey, true, 60);

        return response()->json([
            'message' => 'OTP resent successfully',
            'otp_for_testing' => $otpCode
        ]);
    }

    // ========================= Forgot Password =========================
    public function forgotPassword(Request $request)
{
    $user = auth()->user(); // user الحالي اللي عامل login

    $request->validate([
        'phone' => 'required'
    ]);

   if($request->phone !==$user->phone)
   {
    return response()->json(['message' => 'Phone number does not match the logged-in user'], 403);

   }

    // Rate limit 1 request per 60 seconds
    $cacheKey = 'forgot_password_' . $user->id;
    if (Cache::has($cacheKey)) {
        return response()->json(['message' => 'Please wait before requesting again'], 429);
    }

    // generate OTP / reset code
    $otpCode = rand(100000, 999999);

    // store OTP in otp table (hashed)
    Otp::create([
        'user_id' => $user->id,
        'code' => bcrypt($otpCode),
        'expires_at' => now()->addMinutes(10)
    ]);

    Cache::put($cacheKey, true, 60);

    return response()->json([
        'message' => 'Reset code sent to your phone',
        'otp_for_testing' => $otpCode
    ]);
}


    // ========================= Reset Password =========================
    public function resetPassword(Request $request)
    {
        $request->validate([
            'phone' => 'required',
            'otp' => 'required',
            'password' => 'required|min:6|confirmed'
        ]);

        $user = User::where('phone', $request->phone)->first();
        if (!$user) {
            return response()->json(['message' => 'Phone not registered'], 404);
        }

        $otp = Otp::where('user_id', $user->id)->latest()->first();
        if (!$otp || !Hash::check($request->otp, $otp->code)) {
            return response()->json(['message' => 'Invalid OTP'], 422);
        }

        if (Carbon::parse($otp->expires_at)->isPast()) {
            return response()->json(['message' => 'OTP expired'], 422);
        }

        $user->password = bcrypt($request->password);
        $user->save();

        $otp->delete();

        return response()->json(['message' => 'Password reset successfully']);
    }

    // ========================= Request Change Phone =========================
    public function requestChangePhone(Request $request)
{
    $request->validate([
        'new_phone' => 'required|unique:users,phone',
    ]);

    $user = auth()->user();

    $otp = rand(100000, 999999);

    Cache::put(
        'change_phone_otp_'.$user->id,
        [
            'otp' => $otp,
            'phone' => $request->new_phone
        ],
        now()->addMinutes(5)
    );

    // Send OTP SMS here

    return response()->json([
        'message' => 'OTP sent to new phone',
        'otp_for_testing' => $otp
    ]);
}
    // ========================= Verify Change Phone =========================
public function verifyChangePhone(Request $request)
{
    $request->validate([
        'otp' => 'required'
    ]);

    $user = auth()->user();
    $data = Cache::get('change_phone_otp_'.$user->id);

    if (!$data || $data['otp'] != $request->otp) {
        return response()->json(['message' => 'Invalid OTP'], 400);
    }

    $user->update([
        'phone' => $data['phone'],
        'phone_verified_at' => now(),
    ]);

    Cache::forget('change_phone_otp_'.$user->id);

    return response()->json([
        'message' => 'Phone number updated successfully'
    ]);
}

    // ========================= Change Password =========================
public function changePassword(Request $request)
{
    $request->validate([
        'current_password' => 'required',
        'new_password' => 'required|min:6|confirmed',
    ]);

    $user = auth()->user();

    if (!Hash::check($request->current_password, $user->password)) {
        return response()->json([
            'message' => 'Current password is incorrect'
        ], 400);
    }

    $user->update([
        'password' => Hash::make($request->new_password)
    ]);

    return response()->json([
        'message' => 'Password changed successfully'
    ]);
}



    // ========================= Logout =========================
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Logged out successfully']);
    }

    // ========================= Me =========================
    public function me()
    {
        return response()->json(auth()->user());
    }

    // ========================= Delete Account =========================
    public function deleteAccount()
    {
        $user = auth()->user();
        $user->delete();

        return response()->json(['message' => 'Account deleted successfully']);
    }



}
