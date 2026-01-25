# seed_test_data.py
import random
from faker import Faker
from sqlalchemy.exc import IntegrityError


from app import (
    app, db,
    User, Post,
    UserMedia, Collection, CollectionItem,
    TvSeasonProgress, EpisodeNote,
)

fake = Faker("ru_RU")

def rand_password() -> str:
    # Под твою политику: >=8, разный регистр, минимум 1 цифра
    base = fake.password(length=10, special_chars=False)
    return "A" + base[:-2] + "z9"

def create_users(n: int = 10):
    users = []
    for i in range(n):
        username = f"{fake.user_name()[:20]}_{i}"
        email = f"{username}@example.com"
        u = User(username=username, email=email)
        u.set_password(rand_password())
        users.append(u)
        db.session.add(u)
    db.session.commit()
    return users

def create_posts(users, per_user: int = 2):
    for u in users:
        for _ in range(per_user):
            db.session.add(Post(
                title=fake.sentence(nb_words=6),
                text="\n\n".join(fake.paragraphs(nb=3))
            ))
    db.session.commit()


def create_user_media(users, per_user: int = 25, tv_ratio: float = 0.35):
    statuses = ["planned", "watching", "completed", "dropped", None]
    for u in users:
        used = set()
        for _ in range(per_user):
            media_type = "tv" if random.random() < tv_ratio else "movie"
            tmdb_id = random.randint(1_000, 200_000)

            key = (media_type, tmdb_id)
            if key in used:
                continue
            used.add(key)

            row = UserMedia(
                user_id=u.id,
                media_type=media_type,
                tmdb_id=tmdb_id,
                rating=random.choice([None] + list(range(1, 11))),
                progress=random.choice([None, 0, 10, 50, 90]),
                note=random.choice([None, fake.sentence(nb_words=10)]),
                status=random.choice(statuses),
            )

            if media_type == "tv":
                row.seasons_watched = random.choice([None, 0, 1, 2, 3, 5])
                row.episodes_watched = random.choice([None, 0, 3, 10, 24, 60])

            db.session.add(row)

    db.session.commit()


def create_collections(users, per_user: int = 3, items_per_collection: int = 10):
    for u in users:
        for c in range(per_user):
            col = Collection(
                user_id=u.id,
                title=f"{fake.word().capitalize()} {c + 1}",
                description=random.choice([None, fake.sentence(nb_words=12)]),
                is_public=bool(random.getrandbits(1)),
            )
            db.session.add(col)
            db.session.flush()

            used_items = set()
            for _ in range(items_per_collection):
                media_type = random.choice(["movie", "tv"])
                tmdb_id = random.randint(1_000, 200_000)
                key = (media_type, tmdb_id)
                if key in used_items:
                    continue
                used_items.add(key)

                db.session.add(CollectionItem(
                    collection_id=col.id,
                    media_type=media_type,
                    tmdb_id=tmdb_id
                ))

    db.session.commit()


def create_tv_progress_and_notes(users, max_tv_per_user: int = 6):
    total_seasons = 0
    total_notes = 0
    skipped_notes = 0

    for idx, u in enumerate(users, start=1):
        print(f"[USER {idx}/{len(users)}] id={u.id}")

        with db.session.no_autoflush:
            tv_rows = UserMedia.query.filter_by(
                user_id=u.id,
                media_type="tv"
            ).all()

        random.shuffle(tv_rows)
        tv_rows = tv_rows[:max_tv_per_user]

        used_notes = set()
        used_seasons = set()

        for tv in tv_rows:
            seasons = random.randint(1, 4)
            print(f"  TV {tv.tmdb_id} - сезонов: {seasons}")

            for season in range(1, seasons + 1):
                sp_key = (u.id, tv.tmdb_id, season)
                if sp_key not in used_seasons:
                    used_seasons.add(sp_key)
                    db.session.add(TvSeasonProgress(
                        user_id=u.id,
                        tv_id=tv.tmdb_id,
                        season=season,
                        watched=random.randint(0, 12),
                        status=random.choice(
                            [None, "planned", "watching", "completed", "dropped"]
                        )
                    ))
                    total_seasons += 1
                    print(f"    + season {season}")

                notes_count = random.randint(0, 3)
                attempts = 0
                created = 0

                while created < notes_count and attempts < 20:
                    attempts += 1
                    ep = random.randint(1, 12)
                    key = (u.id, tv.tmdb_id, season, ep)

                    if key in used_notes:
                        skipped_notes += 1
                        continue

                    used_notes.add(key)
                    created += 1
                    total_notes += 1

                    db.session.add(EpisodeNote(
                        user_id=u.id,
                        tv_id=tv.tmdb_id,
                        season=season,
                        episode=ep,
                        note=fake.sentence(nb_words=14),
                    ))
                    print(f"      + note S{season}E{ep}")

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()

    print("------ ИТОГ ------")
    print(f"Сезонов добавлено: {total_seasons}")
    print(f"Заметок добавлено: {total_notes}")
    print(f"Пропущено дублей: {skipped_notes}")

def main():
    with app.app_context():
        db.create_all()
        users = create_users(n=12)
        create_posts(users, per_user=2)
        create_user_media(users, per_user=30, tv_ratio=0.4)
        create_collections(users, per_user=3, items_per_collection=12)
        create_tv_progress_and_notes(users, max_tv_per_user=6)

if __name__ == "__main__":
    main()
