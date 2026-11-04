<?php

use App\Http\Controllers\Api\V1\AuthController;
use App\Http\Controllers\Api\V1\ReferenceController;
use App\Http\Controllers\Api\V1\MediaController;
use App\Http\Controllers\Api\V1\ModerationController;
use App\Http\Controllers\Api\V1\EntryController;
use App\Http\Controllers\Api\V1\UserListController;
use App\Http\Controllers\Api\V1\PublicListController;
use App\Http\Controllers\Api\V1\ProfileController;
use App\Http\Controllers\Api\V1\TmdbController;
use App\Http\Controllers\Api\V1\PersonController;
use Illuminate\Support\Facades\Route;

Route::prefix('v1')->group(function () {
    Route::middleware('throttle:120,1')->group(function () {
        Route::get('/tmdb/search', [TmdbController::class, 'search']);
        Route::get('/tmdb/details', [TmdbController::class, 'details']);
        
        Route::get('persons/{id}', [PersonController::class, 'show']);

        Route::prefix('reference')->group(function () {
            Route::get('types', [ReferenceController::class, 'types']);
            Route::get('statuses', [ReferenceController::class, 'statuses']);
            Route::get('roles', [ReferenceController::class, 'roles']);
            Route::get('genres', [ReferenceController::class, 'genres']);
        });

        Route::get('media/random', [MediaController::class, 'random']);
        Route::get('media', [MediaController::class, 'index']);
        Route::get('media/{id}', [MediaController::class, 'show']);
        Route::get('media/{id}/similar', [MediaController::class, 'similar']);

        Route::prefix('public')->group(function () {
            Route::get('lists/{token}', [PublicListController::class, 'show']);
        });
    });

    
    Route::prefix('auth')->group(function () {
        Route::post('register', [AuthController::class, 'register'])->middleware('throttle:10,1');
        Route::post('login', [AuthController::class, 'login'])->middleware('throttle:10,1');

        Route::middleware('auth:sanctum')->group(function () {
            Route::post('logout', [AuthController::class, 'logout']);
            Route::get('me', [AuthController::class, 'me']);
        });
    });

    Route::middleware(['auth:sanctum', 'throttle:60,1'])->group(function () {
        Route::prefix('entries')->group(function () {
            Route::get('/', [EntryController::class, 'index']);
            Route::get('/{id}', [EntryController::class, 'show']);
            Route::post('/', [EntryController::class, 'store']);
            Route::delete('/{id}', [EntryController::class, 'destroy']);
        });

        Route::get('profile', [ProfileController::class, 'show']);
        Route::put('profile', [ProfileController::class, 'update']);

        Route::prefix('lists')->group(function () {
            Route::get('/', [UserListController::class, 'index']);
            Route::post('/', [UserListController::class, 'store']);
            Route::get('/{id}', [UserListController::class, 'show']);
            Route::post('/{id}/media', [UserListController::class, 'addMedia']);
            Route::delete('/{id}/media/{media_id}', [UserListController::class, 'removeMedia']);
        });

        Route::prefix('moderation')->group(function () {
            Route::post('requests', [ModerationController::class, 'store']);
            Route::get('requests', [ModerationController::class, 'index']);
            Route::post('requests/{moderationRequest}/approve', [ModerationController::class, 'approve']);
            Route::post('requests/{moderationRequest}/reject', [ModerationController::class, 'reject']);
        });
    });

    Route::middleware('auth:sanctum')->group(function () {
        Route::post('media', [MediaController::class, 'store'])->middleware('throttle:5,1');
        Route::put('media/{id}', [MediaController::class, 'update'])->middleware('throttle:5,1');
    });

});