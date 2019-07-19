<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\User;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Validation\ValidationException;
use JWTAuth;
use Nexmo\Laravel\Facade\Nexmo;
use Nexmo\Verify\Verification;

class AuthController extends Controller
{
    /**
     * @param Request $request
     *
     * @return JsonResponse
     * @throws ValidationException
     */
    public function verify(Request $request)
    {
        $this->validate($request, [
            'phone' => 'required|integer',
        ]);

        $user = User::wherePhone($request->get('phone'))->first();
        if (!$user) {
            throw new ModelNotFoundException('User not found');
        }

        try {
            $verification = Nexmo::verify()->start([
                'number' => $user->phone,
                'brand' => 'Laravel Nexmo',
            ]);
        } catch (\Exception $exception) {
            return response()->json([
                'message' => $exception->getMessage(),
            ], Response::HTTP_BAD_REQUEST);
        }

        $user->verification_id = $verification->getRequestId();
        $user->save();

        return response()->json([
            'verification_id' => $verification->getRequestId(),
        ], Response::HTTP_OK);
    }

    /**
     * @param Request $request
     *
     * @return JsonResponse
     * @throws ValidationException
     */
    public function login(Request $request)
    {
        $this->validate($request, [
            'code' => 'required',
            'verification_id' => 'required',
        ]);

        $verification = $request->get('verification_id');
        $code = $request->get('code');

        $user = User::whereVerificationId($verification)->first();

        if (!$user) {
            throw new ModelNotFoundException('User not found.');
        }

        try {
            $verification = new Verification($verification);
            Nexmo::verify()->check($verification, $code);
        } catch (\Exception $exception) {
            return response()->json([
                'message' => $exception->getMessage(),
            ], Response::HTTP_BAD_REQUEST);
        }

        $user->verification_id = null;
        $user->code = $code;
        $user->save();

        return $this->respondWithToken($this->generateToken($user));
    }

    /**
     * @param string $token
     *
     * @return JsonResponse
     */
    protected function respondWithToken(string $token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
        ]);
    }

    /**
     * @param User $user
     *
     * @return mixed
     */
    protected function generateToken(User $user)
    {
        return JWTAuth::fromUser($user);
    }
}