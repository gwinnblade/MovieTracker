<?php

namespace Tests\Feature;

use App\Models\Entry;
use App\Models\Episode;
use App\Models\Media;
use App\Models\Status;
use App\Models\Type;
use App\Models\User;
use Database\Seeders\DictionarySeeder;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

class TrackerTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->seed(DictionarySeeder::class);
        config(['services.tmdb.api_key' => 'test-token', 'sanctum.stateful' => ['localhost:3002']]);
        Http::preventStrayRequests();
        $this->withHeaders(['Origin' => 'http://localhost:3002', 'Referer' => 'http://localhost:3002/']);
    }

    private function media(string $type = 'movie', string $visibility = 'external'): Media
    {
        return Media::create(['title_ru' => 'Тестовое кино', 'type_id' => Type::where('code', $type === 'tv' ? 'series' : 'movie')->value('id'),
            'moderation_status' => $visibility, 'tmdb_id' => $type === 'tv' ? 1396 : 550, 'tmdb_type' => $type]);
    }

    private function movieResponse(): array
    {
        return ['id' => 550, 'title' => 'Бойцовский клуб', 'original_title' => 'Fight Club', 'overview' => 'Описание',
            'release_date' => '1999-10-15', 'poster_path' => '/poster.jpg', 'vote_average' => 8.4, 'runtime' => 139,
            'genres' => [['id' => 18, 'name' => 'драма']], 'production_companies' => [['name' => 'Studio']],
            'credits' => ['crew' => [['id' => 7467, 'name' => 'David Fincher', 'job' => 'Director', 'profile_path' => '/director.jpg']],
                'cast' => [['id' => 819, 'name' => 'Edward Norton', 'character' => 'Narrator', 'profile_path' => '/actor.jpg']]]];
    }

    public function test_registration_starts_a_session_and_logout_ends_it(): void
    {
        $this->postJson('/api/v1/auth/register', ['name' => 'Киноман', 'login' => 'film-fan', 'email' => 'fan@example.test',
            'password' => 'NewPassword2026!', 'password_confirmation' => 'NewPassword2026!', 'role' => 'admin'])->assertCreated()->assertJsonPath('role', 'user');
        $this->getJson('/api/v1/auth/me')->assertOk()->assertJsonPath('login', 'film-fan');
        $this->postJson('/api/v1/auth/logout')->assertOk();
        $this->assertGuest('web');
        // A real HTTP request creates new guards; the test app is reused.
        $this->app['auth']->forgetGuards();
        $this->getJson('/api/v1/auth/me')->assertUnauthorized();
    }

    public function test_tmdb_tracking_does_not_publish_before_moderation_and_approval_is_once(): void
    {
        Http::fake(['https://api.themoviedb.org/3/movie/550*' => Http::response($this->movieResponse())]);
        $author = User::factory()->create();
        $moderator = User::factory()->create(['role' => 'moderator']);
        $this->actingAs($author)->postJson('/api/v1/tmdb/save', ['tmdb_id' => 550, 'tmdb_type' => 'movie'])->assertOk()->assertJsonPath('moderation_status', 'external');
        $media = Media::firstOrFail();
        $this->getJson('/api/v1/media')->assertOk()->assertJsonPath('total', 0);
        $response = $this->postJson('/api/v1/moderation/requests', ['title_ru' => 'Бойцовский клуб', 'type_id' => $media->type_id, 'tmdb_id' => 550, 'tmdb_type' => 'movie'])->assertCreated();
        $id = $response->json('id');
        $this->postJson('/api/v1/moderation/requests', ['title_ru' => 'Повтор', 'type_id' => $media->type_id, 'tmdb_id' => 550, 'tmdb_type' => 'movie'])->assertConflict();
        $this->postJson('/api/v1/moderation/requests/'.$id.'/approve')->assertForbidden();
        $this->actingAs($moderator)->postJson('/api/v1/moderation/requests/'.$id.'/approve')->assertOk()->assertJsonPath('media_id', $media->id);
        $this->postJson('/api/v1/moderation/requests/'.$id.'/approve')->assertConflict();
        $this->postJson('/api/v1/moderation/requests/'.$id.'/reject', ['reason' => 'Повтор'])->assertConflict();
        $this->getJson('/api/v1/media')->assertOk()->assertJsonPath('total', 1)->assertJsonPath('data.0.title_ru', 'Бойцовский клуб');
        $this->assertDatabaseCount('media', 1);
        $this->assertDatabaseHas('moderation_requests', ['id' => $id, 'status' => 'approved', 'moderator_id' => $moderator->id]);
        $this->assertDatabaseHas('persons', ['tmdb_id' => 7467, 'photo_key' => '/director.jpg']);
        $this->assertDatabaseHas('person_media', ['media_id' => $media->id, 'character' => 'Narrator']);
        $this->getJson('/api/v1/media?search='.urlencode('бойцовский'))->assertOk()->assertJsonPath('total', 1);
    }

    public function test_authors_see_only_their_requests_and_rejection_reason(): void
    {
        $author = User::factory()->create();
        $other = User::factory()->create();
        $admin = User::factory()->create(['role' => 'admin']);
        $type = Type::first()->id;
        $id = $this->actingAs($author)->postJson('/api/v1/moderation/requests', ['title_ru' => 'Новый фильм', 'type_id' => $type])->assertCreated()->json('id');
        $this->actingAs($other)->getJson('/api/v1/moderation/requests')->assertOk()->assertJsonCount(0);
        $this->actingAs($admin)->postJson('/api/v1/moderation/requests/'.$id.'/reject', ['reason' => 'Уточните год выхода'])->assertOk();
        $this->actingAs($author)->getJson('/api/v1/moderation/requests')->assertOk()->assertJsonPath('0.rejection_reason', 'Уточните год выхода');
        $this->getJson('/api/v1/media')->assertJsonPath('total', 0);
    }

    public function test_collections_crud_privacy_and_idempotent_membership(): void
    {
        $owner = User::factory()->create();
        $other = User::factory()->create();
        $media = $this->media();
        $response = $this->actingAs($owner)->postJson('/api/v1/lists', ['name' => 'Моя подборка', 'description' => 'Описание', 'is_public' => true])->assertCreated();
        $id = $response->json('id');
        $token = $response->json('share_token');
        $this->postJson('/api/v1/lists/'.$id.'/media', ['media_id' => $media->id])->assertOk();
        $this->postJson('/api/v1/lists/'.$id.'/media', ['media_id' => $media->id])->assertOk();
        $this->assertDatabaseCount('list_media', 1);
        $this->getJson('/api/v1/public/lists/'.$token)->assertOk()->assertJsonPath('data.description', 'Описание');
        $this->actingAs($other)->deleteJson('/api/v1/lists/'.$id)->assertNotFound();
        $this->postJson('/api/v1/lists/'.$id.'/media', ['media_id' => $media->id])->assertNotFound();
        $this->actingAs($owner)->putJson('/api/v1/lists/'.$id, ['name' => 'Другое название', 'description' => 'Новое описание', 'is_public' => false])->assertOk();
        $this->getJson('/api/v1/public/lists/'.$token)->assertNotFound();
        $this->actingAs($other)->getJson('/api/v1/public/collections/'.$id)->assertNotFound();
        $this->actingAs($owner)->deleteJson('/api/v1/lists/'.$id.'/media/'.$media->id)->assertOk();
        $this->assertDatabaseCount('list_media', 0);
        $this->deleteJson('/api/v1/lists/'.$id)->assertOk();
        $this->assertDatabaseCount('user_lists', 0);
    }

    public function test_season_progress_is_clamped_and_episode_notes_are_personal(): void
    {
        Http::fake(['https://api.themoviedb.org/3/tv/1396/season/1*' => Http::response(['season_number' => 1, 'name' => 'Первый сезон',
            'episodes' => [['episode_number' => 1, 'season_number' => 1, 'name' => 'Pilot'], ['episode_number' => 2, 'season_number' => 1, 'name' => 'Second']]])]);
        $user = User::factory()->create();
        $other = User::factory()->create();
        $media = $this->media('tv');
        $this->actingAs($user)->putJson('/api/v1/media/'.$media->id.'/seasons/1/progress', ['watched' => 999])->assertOk()->assertJsonPath('watched', 2)->assertJsonPath('status', 'completed');
        $url = '/api/v1/media/'.$media->id.'/seasons/1/episodes/2/note';
        $this->putJson($url, ['note' => 'Личный текст'])->assertOk();
        $this->putJson($url, ['note' => 'Обновлённый текст'])->assertOk();
        $this->assertDatabaseCount('episode_notes', 1);
        $this->actingAs($other)->getJson('/api/v1/media/'.$media->id.'/tracking')->assertOk()->assertJsonCount(0, 'episode_notes')->assertJsonCount(0, 'seasons');
        $this->actingAs($user)->putJson('/api/v1/media/'.$media->id.'/seasons/1/episodes/99/note', ['note' => 'Invalid'])->assertUnprocessable();
        $this->putJson($url, ['note' => ''])->assertOk();
        $this->assertDatabaseCount('episode_notes', 0);
        $this->getJson('/api/v1/media/'.$media->id.'/seasons/1')->assertOk()->assertJsonPath('episodes.0.title', 'Pilot');
        $this->assertDatabaseCount('episodes', 2);
    }

    public function test_entries_filter_sort_statistics_and_episode_ownership(): void
    {
        $user = User::factory()->create();
        $other = User::factory()->create();
        $movie = $this->media();
        $series = $this->media('tv');
        $status = Status::where('code', 'completed')->value('id');
        $this->actingAs($user)->postJson('/api/v1/entries', ['media_id' => $movie->id, 'status_id' => $status, 'rating' => 9, 'note' => 'Хорошо'])->assertCreated();
        $this->postJson('/api/v1/entries', ['media_id' => $series->id, 'status_id' => $status, 'rating' => 3])->assertCreated();
        $this->getJson('/api/v1/entries?sort=rating_asc')->assertOk()->assertJsonPath('data.0.rating', 3);
        $this->getJson('/api/v1/entries?type_id='.$movie->type_id)->assertJsonPath('total', 1);
        $this->getJson('/api/v1/profile')->assertOk()->assertJsonPath('stats.watched', 2)->assertJsonPath('stats.avg_rating', 6)->assertJsonPath('stats.movies', 1)->assertJsonPath('stats.series', 1);
        $episode = Episode::create(['media_id' => $series->id, 'season' => 1, 'number' => 1, 'title' => 'Episode']);
        $this->postJson('/api/v1/entries', ['media_id' => $movie->id, 'status_id' => $status, 'episodes' => [['episode_id' => $episode->id, 'watched' => true]]])->assertUnprocessable();
        $entry = Entry::where('media_id', $movie->id)->firstOrFail();
        $this->actingAs($other)->deleteJson('/api/v1/entries/'.$entry->id)->assertNotFound();
        $this->actingAs($user)->deleteJson('/api/v1/entries/'.$entry->id)->assertOk();
    }

    public function test_avatar_cover_uploads_and_password_changes(): void
    {
        Storage::fake('public');
        $user = User::factory()->create(['password' => 'OldPassword2026!']);
        $this->actingAs($user)->post('/api/v1/profile', ['name' => $user->name, 'login' => $user->login, 'email' => $user->email,
            'current_password' => 'OldPassword2026!', 'password' => 'ChangedPassword2026!', 'password_confirmation' => 'ChangedPassword2026!',
            'avatar' => UploadedFile::fake()->image('avatar.png')], ['Accept' => 'application/json'])->assertOk();
        Storage::disk('public')->assertExists($user->fresh()->avatar_key);
        $this->assertTrue(Hash::check('ChangedPassword2026!', $user->fresh()->getAuthPassword()));
        $response = $this->post('/api/v1/lists', ['name' => 'С обложкой', 'is_public' => '0', 'cover' => UploadedFile::fake()->image('cover.jpg')], ['Accept' => 'application/json'])->assertCreated();
        $this->assertNotNull($response->json('cover_url'));
    }

    public function test_password_recovery_token_is_single_use(): void
    {
        Notification::fake();
        $user = User::factory()->create();
        $this->postJson('/api/v1/auth/forgot-password', ['email' => $user->email])->assertOk();
        $token = null;
        Notification::assertSentTo($user, ResetPassword::class, function ($notification) use (&$token) {
            $token = $notification->token;

            return true;
        });
        $payload = ['email' => $user->email, 'token' => $token, 'password' => 'RecoveredPassword2026!', 'password_confirmation' => 'RecoveredPassword2026!'];
        $this->postJson('/api/v1/auth/reset-password', $payload)->assertOk();
        $this->assertTrue(Hash::check('RecoveredPassword2026!', $user->fresh()->getAuthPassword()));
        $this->postJson('/api/v1/auth/reset-password', $payload)->assertUnprocessable();
    }

    public function test_tmdb_failures_are_reported_without_exposing_the_token(): void
    {
        Http::fake(['https://api.themoviedb.org/3/trending/movie/week*' => Http::response(['status_message' => 'Invalid API key'], 401)]);
        $response = $this->getJson('/api/v1/tmdb/trending?type=movie')->assertStatus(503);
        $this->assertStringContainsString('TMDB', $response->json('message'));
        $this->assertStringNotContainsString('test-token', $response->getContent());
    }
}
