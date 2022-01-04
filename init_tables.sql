CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name TEXT,
  password TEXT
);

CREATE TABLE IF NOT EXISTS trip (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  country TEXT,
  start_date DATE,
  end_date DATE
);

CREATE TABLE IF NOT EXISTS day (
  id SERIAL PRIMARY KEY,
  trip_id INTEGER REFERENCES trip(id),
  day_num INTEGER,
  date DATE
);

CREATE TABLE IF NOT EXISTS category (
  id SERIAL PRIMARY KEY,
  type TEXT
);


CREATE TABLE IF NOT EXISTS activity (
  id SERIAL PRIMARY KEY,
  day_id INTEGER REFERENCES day(id),
  category_id INTEGER REFERENCES category(id),
  details TEXT,
  start_time TIME,
  end_time TIME,
  comments TEXT,
  transport_type TEXT,
  transport_duration TEXT
);

-- CREATE TABLE IF NOT EXISTS activity_photos (
--   id SERIAL PRIMARY KEY,
--   activity_id INTEGER REFERENCES activity(id),
--   photo TEXT
-- );

CREATE TABLE IF NOT EXISTS buddy (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  buddy_user_id INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS buddy_trip (
  id SERIAL PRIMARY KEY,
  buddy_id INTEGER,
  trip_id INTEGER REFERENCES trip(id)
);

CREATE TABLE IF NOT EXISTS tempDay (
  id SERIAL PRIMARY KEY,
  trip_id INTEGER REFERENCES trip(id),
  day_num INTEGER,
  date DATE,
  old_day_id INTEGER
);

CREATE TABLE IF NOT EXISTS tempActivity (
  id SERIAL PRIMARY KEY,
  day_id INTEGER,
  category_id INTEGER REFERENCES category(id),
  details TEXT,
  start_time TIME,
  end_time TIME,
  comments TEXT,
  transport_type TEXT,
  transport_duration TEXT
);