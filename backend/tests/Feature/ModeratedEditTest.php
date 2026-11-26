<?php

namespace Tests\Feature;

use App\Models\Genre;
use App\Models\Media;
use App\Models\Type;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class ModeratedEditTest extends TestCase
{
    use RefreshDatabase;

    public function test_edits_are_unpublished_until_approved_and_can_remove_genres(): void
    {
        $this->seed(\Database\Seeders\DictionarySeeder::class);
        $author = User::factory()->create();
        $admin = User::factory()->create(['role' => 'admin']);
        $media = Media::create(['title_ru' => 'Старое название', 'type_id' => Type::first()->id, 'release_date' => '1999-10-15', 'moderation_status' => 'approved']);
        $media->genres()->attach(Genre::first()->id);
        $id = $this->actingAs($author)->postJson('/api/v1/moderation/requests', ['media_id' => $media->id, 'title_ru' => 'Исправленное название',
            'type_id' => $media->type_id, 'release_year' => 2001, 'clear_genres' => true])->assertCreated()->json('id');
        $this->assertSame('Старое название', $media->fresh()->title_ru);
        $this->actingAs($admin)->postJson('/api/v1/moderation/requests/'.$id.'/approve')->assertOk();
        $this->assertSame('Исправленное название', $media->fresh()->title_ru);
        $this->assertSame('2001-01-01', $media->fresh()->release_date->format('Y-m-d'));
        $this->assertCount(0, $media->fresh()->genres);
        $this->assertDatabaseCount('media', 1);
    }
}
