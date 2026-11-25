<?php

use App\Http\Controllers\Api\V1\AuthController;
use App\Http\Controllers\Api\V1\DashboardController;
use App\Http\Controllers\Api\V1\EntryController;
use App\Http\Controllers\Api\V1\MediaController;
use App\Http\Controllers\Api\V1\ModerationController;
use App\Http\Controllers\Api\V1\PersonController;
use App\Http\Controllers\Api\V1\ProfileController;
use App\Http\Controllers\Api\V1\PublicListController;
use App\Http\Controllers\Api\V1\ReferenceController;
use App\Http\Controllers\Api\V1\TmdbController;
use App\Http\Controllers\Api\V1\TrackingController;
use App\Http\Controllers\Api\V1\UserListController;
use Illuminate\Support\Facades\Route;

Route::prefix('v1')->group(function () {
    Route::middleware('throttle:180,1')->group(function () {
        Route::get('summary', [DashboardController::class, 'summary']);
        Route::get('tmdb/trending', [TmdbController::class, 'trending']);
        Route::get('tmdb/search', [TmdbController::class, 'search']);
        Route::get('tmdb/details', [TmdbController::class, 'details']);
        Route::get('tmdb/tv/{id}/season/{season}', [TmdbController::class, 'season']);
        Route::get('persons/{id}', [PersonController::class, 'show']);
        foreach (['types', 'statuses', 'roles', 'genres'] as $reference) {
            Route::get('reference/'.$reference, [ReferenceController::class, $reference]);
        }
        Route::get('media/random', [MediaController::class, 'random']);
        Route::get('media', [MediaController::class, 'index']);
        Route::get('media/{id}', [MediaController::class, 'show'])->whereNumber('id');
        Route::get('media/{id}/similar', [MediaController::class, 'similar'])->whereNumber('id');
        Route::get('media/{media}/seasons/{season}', [TrackingController::class, 'season'])->whereNumber('season');
        Route::get('public/lists/{token}', [PublicListController::class, 'show']);
        Route::get('public/collections/{id}', [PublicListController::class, 'byId']);
    });

    Route::prefix('auth')->middleware('throttle:10,1')->group(function () {
        Route::post('register', [AuthController::class, 'register']);
        Route::post('login', [AuthController::class, 'login']);
        Route::post('forgot-password', [AuthController::class, 'forgotPassword']);
        Route::post('reset-password', [AuthController::class, 'resetPassword']);
    });

    Route::middleware(['auth:sanctum', 'throttle:180,1'])->group(function () {
        Route::get('auth/me', [AuthController::class, 'me']);
        Route::post('auth/logout', [AuthController::class, 'logout']);
        Route::post('tmdb/save', [TmdbController::class, 'save']);
        Route::get('recommendations', [DashboardController::class, 'recommendations']);
        Route::get('entries', [EntryController::class, 'index']);
        Route::get('entries/{id}', [EntryController::class, 'show']);
        Route::post('entries', [EntryController::class, 'store']);
        Route::delete('entries/{id}', [EntryController::class, 'destroy']);
        Route::get('media/{media}/tracking', [TrackingController::class, 'show']);
        Route::put('media/{media}/seasons/{season}/progress', [TrackingController::class, 'progress']);
        Route::put('media/{media}/seasons/{season}/episodes/{episode}/note', [TrackingController::class, 'note']);
        Route::get('profile', [ProfileController::class, 'show']);
        Route::put('profile', [ProfileController::class, 'update']);
        Route::post('profile', [ProfileController::class, 'update']);
        Route::get('lists', [UserListController::class, 'index']);
        Route::post('lists', [UserListController::class, 'store']);
        Route::get('lists/{id}', [UserListController::class, 'show']);
        Route::put('lists/{id}', [UserListController::class, 'update']);
        Route::post('lists/{id}', [UserListController::class, 'update']);
        Route::delete('lists/{id}', [UserListController::class, 'destroy']);
        Route::post('lists/{id}/media', [UserListController::class, 'addMedia']);
        Route::delete('lists/{id}/media/{mediaId}', [UserListController::class, 'removeMedia']);
        Route::get('moderation/requests', [ModerationController::class, 'index']);
        Route::post('moderation/requests', [ModerationController::class, 'store'])->middleware('throttle:15,1');
        Route::post('moderation/requests/{moderationRequest}/approve', [ModerationController::class, 'approve']);
        Route::post('moderation/requests/{moderationRequest}/reject', [ModerationController::class, 'reject']);
        Route::post('media', [ModerationController::class, 'store']);
    });
});
