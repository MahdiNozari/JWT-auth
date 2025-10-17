<?php

namespace App\Traits;

trait ApiResponse
{
     public function successResponse($data,$code = 200,$message=null)
    {
        return response()->json([
            'status' => 'success',
            'message' => $message,
            'data' => $data
        ],$code);
    }

    public function errorResponse($message,$code)
    {
        return response()->json([
            'status' => 'error',
            'message' => $message,
            'data' => null
        ],$code);
    }
}
