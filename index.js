import express from 'express';
import pg from 'pg';
import methodOverride from 'method-override';
import cookieParser from 'cookie-parser';
import jsSHA from 'jssha';
import multer from 'multer';
import { DateTime } from 'luxon';

const { Pool } = pg;

const PORT = process.argv[2];

// create separate DB connection configs for production vs non-production environments.
// ensure our server still works on our local machines.
let pgConnectionConfigs;
if (process.env.ENV === 'PRODUCTION') {
  // determine how we connect to the remote Postgres server
  pgConnectionConfigs = {
    user: 'postgres',
    // set DB_PASSWORD as an environment variable for security.
    password: process.env.DB_PASSWORD,
    host: 'localhost',
    database: 'holiyay',
    port: 5432,
  };
} else {
  // determine how we connect to the local Postgres server
  pgConnectionConfigs = {
    user: 'jyjyjiayi',
    host: 'localhost',
    database: 'holiyay',
    port: 5432,
  };
}

const pool = new Pool(pgConnectionConfigs);

const app = express();

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: false }));
app.use(methodOverride('_method'));
app.use(cookieParser());
app.use(express.static('uploads'));

// set the name of the upload directory here
const multerUpload = multer({ dest: 'uploads/' });

// initialize salt as a global constant
const { SALT } = process.env;

const getHash2 = (input) => {
  // create new SHA object
  const shaObj = new jsSHA('SHA-512', 'TEXT', { encoding: 'UTF8' });

  // create an unhashed cookie string based on user ID and salt
  const unhashedString = `${input}-${SALT}`;

  // generate a hashed cookie string using SHA object
  shaObj.update(unhashedString);

  return shaObj.getHash('HEX');
};

app.use((request, response, next) => {
  // set the default value
  request.isUserLoggedIn = false;

  // check to see if the cookies you need exists
  if (request.cookies.loggedInHash && request.cookies.userId) {
    // get the hased value that should be inside the cookie
    const hash = getHash2(request.cookies.userId);

    // test the value of the cookie
    if (request.cookies.loggedInHash === hash) {
      request.isUserLoggedIn = true;

      // look for this user in the database
      const values = [request.cookies.userId];

      // try to get the user
      pool.query('SELECT * FROM users WHERE id=$1', values, (error, result) => {
        if (error) {
          response.status(503).send('sorry!');
          return;
        }

        // set the user as a key in the request object so that it's accessible in the route
        request.user = result.rows[0];
        console.log('request.user :>> ', request.user);
        next();
      });
      // make sure we don't get down to the next() below
      return;
    }
  }

  next();
});

// Welcome Page
app.get('/', (req, res) => {
  res.render('welcome-page');
});

// Render a form that will sign up a user
app.get('/signup', (request, response) => {
  const { isUserLoggedIn } = request.cookies;
  response.render('signup', { isUserLoggedIn });
});

// Accept a POST request to create a user
app.post('/signup', multerUpload.single('photo'), (request, response) => {
  // initialise the SHA object
  const shaObj = new jsSHA('SHA-512', 'TEXT', { encoding: 'UTF8' });

  // input the password from the request to the SHA object
  shaObj.update(request.body.password);

  // get the hashed password as output from the SHA object
  const hashedPassword = shaObj.getHash('HEX');

  const inputName = request.body.name;

  console.log('actual pw', request.body.password);
  console.log('hashed pw', hashedPassword);
  console.log('request.file :>> ', request.file);

  let values = [];
  const inputPassword = hashedPassword;
  if (request.file === undefined) {
    values = [inputName, inputPassword, 'default'];
  }
  else {
    values = [inputName, inputPassword, request.file.filename];
  }
  pool.query(
    'INSERT INTO users (name, password, photo) VALUES ($1, $2, $3)',
    values,
    (error, result) => {
      if (error) {
        console.log('Sign Up error', error);
      } else {
        console.log(result.rows);
        response.redirect('/login');
      }
    },
  );
});

// Render a form that will log a user in
app.get('/login', (request, response) => {
  const { isUserLoggedIn } = request.cookies;
  response.render('login', { isUserLoggedIn });
});

// Accept a POST request to log a user in
app.post('/login', (request, response) => {
  // retrieve the user entry using their username
  const values = [request.body.name];

  pool.query('SELECT * from users WHERE name=$1', values, (error, result) => {
    // return if there is a query error
    if (error) {
      console.log('Log In Error', error.stack);
      response.status(503).send('Log In unsuccessful');
      return;
    }

    // we didnt find a user with that username
    if (result.rows.length === 0) {
      // the error for incorrect username and incorrect password are the same for security reasons.
      // This is to prevent detection of whether a user has an account for a given service.
      response.status(403).send('login failed! there is no user with that username');
      return;
    }

    // get user record from results
    const user = result.rows[0];
    // initialise SHA object
    const shaObj = new jsSHA('SHA-512', 'TEXT', { encoding: 'UTF8' });
    // input the password from the request to the SHA object
    shaObj.update(request.body.password);
    // get the hashed value as output from the SHA object
    const hashedPassword = shaObj.getHash('HEX');

    // If the user's hashed password in the database does not match the hashed input password, login fails
    if (user.password !== hashedPassword) {
      // the error for incorrect username and incorrect password are the same for security reasons.
      // This is to prevent detection of whether a user has an account for a given service.
      response.status(403).send('login failed! incorrect password');
      return;
    }

    // The user's password hash matches that in the DB and we authenticate the user.

    // create new SHA object
    const shaObj2 = new jsSHA('SHA-512', 'TEXT', { encoding: 'UTF8' });
    // create an unhashed cookie string based on user ID and salt
    const unhashedCookieString = `${user.id}-${SALT}`;

    // generate a hashed cookie string using SHA object
    shaObj2.update(unhashedCookieString);
    const hashedCookieString = shaObj2.getHash('HEX');

    // set the loggedInHash and userId cookies in the response
    response.cookie('loggedInHash', hashedCookieString);

    response.cookie('isUserLoggedIn', true);
    response.cookie('userId', user.id);
    response.redirect('/user-dashboard');
  });
});

app.delete('/logout', (request, response) => {
  response.clearCookie('isUserLoggedIn');
  response.clearCookie('userId');
  response.redirect('/');
});

app.get('/user-dashboard', (req, res) => {
  if (req.isUserLoggedIn === false) {
    res.status(403).send('sorry you are not logged in');
    return;
  }
  const { userId } = req.cookies;
  let userName = '';
  let userPhoto = '';
  let userData = '';
  pool.query(`SELECT * FROM users WHERE users.id=${userId}`).then((result) => {
    userName = result.rows[0].name;
    userPhoto = result.rows[0].photo;
    return pool.query(`SELECT trip.id AS trip_id, trip.user_id, trip.country, trip.start_date, trip.end_date, users.name FROM trip INNER JOIN users ON trip.user_id = users.id WHERE users.id=${userId}`);
  }).then((result2) => {
    userData = result2.rows;
    return pool.query(`SELECT trip.id AS trip_id, trip.user_id, trip.country, trip.start_date, trip.end_date
    FROM trip
    INNER JOIN buddy_trip
    ON trip.id = buddy_trip.trip_id
    WHERE buddy_trip.buddy_id =${userId}`);
  }).then((result3) => {
    const tripsBuddiesCreated = result3.rows;
    res.render('user-dashboard', {
      userName, userPhoto, userData, tripsBuddiesCreated,
    });
  })
    .catch((error) => {
      console.log('select user and trip tables query error', error);
      res.status(400).send('Sorry, there is an error.');
    });
});

// render a form that will add a new trip
app.get('/new-trip', (req, res) => {
  if (req.isUserLoggedIn === false) {
    res.status(403).send('sorry you are not logged in');
    return;
  }
  res.render('new-trip');
});

// accept a POST request to add a new trip
app.post('/new-trip', (req, res) => {
  const tripData = req.body;
  const tripInsertQueryArr = [Number(req.cookies.userId), tripData.country, tripData.start_date, tripData.end_date];
  pool.query('INSERT INTO trip (user_id, country, start_date, end_date) VALUES ($1, $2, $3, $4) RETURNING *', tripInsertQueryArr)
    .then((result) => {
      const startDate = new Date(result.rows[0].start_date);
      const endDate = new Date(result.rows[0].end_date);
      const numOfDays = ((endDate - startDate) / (24 * 3600 * 1000)) + 1;

      let dayQueryDoneCounter = 0;
      for (let i = 1; i <= numOfDays; i += 1) {
        const currentDate = new Date(result.rows[0].start_date.valueOf());
        currentDate.setDate(currentDate.getDate() + i - 1);
        const dayQueryArr = [result.rows[0].id, i, currentDate];
        pool.query('INSERT INTO day (trip_id, day_num, date) VALUES ($1, $2, $3)', dayQueryArr).catch((error) => {
          console.log('insert day table query error', error);
          res.status(400).send('Sorry, there is an error.');
        });
        dayQueryDoneCounter += 1;
      }
      if (dayQueryDoneCounter === numOfDays) {
        res.redirect('/user-dashboard');
      }
    }).catch((error) => {
      console.log('insert trip table query error', error);
      res.status(400).send('Sorry, there is an error.');
    });
});

// render edit form for trip
app.get('/trip/:id/edit', (req, res) => {
  if (req.isUserLoggedIn === false) {
    res.status(403).send('sorry you are not logged in');
    return;
  }
  const tripId = Number(req.params.id);
  pool.query(`SELECT * FROM trip WHERE id = ${tripId}`).then((result) => {
    const tripData = result.rows[0];
    const startDate = DateTime.fromISO(tripData.start_date.toISOString());
    const endDate = DateTime.fromISO(tripData.end_date.toISOString());
    const startDateFormatted = startDate.toISODate();
    const endDateFormatted = endDate.toISODate();
    res.render('trip-edit', { tripData, startDateFormatted, endDateFormatted });
  }).catch((error) => {
    console.log('Select trip table query error', error);
    res.status(400).send('Sorry, there is an error.');
  });
});

// accept a request to edit to edit a trip
app.put('/trip/:id', (req, res) => {
  if (req.isUserLoggedIn === false) {
    res.status(403).send('sorry you are not logged in');
    return;
  }
  const tripId = Number(req.params.id);
  const oldDayIdArr = [];
  pool.query(`INSERT INTO tempDay (trip_id, day_num, date, old_day_id) SELECT day.trip_id, day.day_num, day.date, day.id FROM day INNER JOIN trip ON day.trip_id = trip.id WHERE trip.id=${tripId} RETURNING* `).then((result) => {
    result.rows.forEach((element) => {
      oldDayIdArr.push(element.old_day_id);
    });
    let insertDayQueryDoneCounter = 0;
    for (let i = 0; i < oldDayIdArr.length; i += 1) {
      pool.query(`INSERT INTO tempActivity (day_id, category_id, details, start_time, end_time, comments, transport_type, transport_duration) SELECT activity.day_id, activity.category_id, activity.details, activity.start_time, activity.end_time, activity.comments, activity.transport_type, activity.transport_duration FROM activity INNER JOIN day ON activity.day_id = day.id WHERE day.id = ${oldDayIdArr[i]}`)
        .then(() => {
          pool.query(`DELETE from activity WHERE activity.day_id=${oldDayIdArr[i]}`).catch((error3) => {
            console.log('delete activity table query error', error3);
            res.status(400).send('Sorry, there is an error.');
          });
        }).catch((error2) => {
          console.log('insert tempActivity table query error', error2);
          res.status(400).send('Sorry, there is an error.');
        });
      insertDayQueryDoneCounter += 1;
    }
    if (insertDayQueryDoneCounter === oldDayIdArr.length) {
      pool.query(`DELETE from day WHERE day.trip_id=${tripId}`);
    }// left here
  }).then(() => {
    const newTripData = req.body;
    return pool.query(`UPDATE trip SET country='${newTripData.country}', start_date='${newTripData.start_date}', end_date='${newTripData.end_date}' WHERE id=${tripId} RETURNING *`);
  }).then((result2) => {
    const startDate = new Date(result2.rows[0].start_date);
    const endDate = new Date(result2.rows[0].end_date);
    const numOfDays = ((endDate - startDate) / (24 * 3600 * 1000)) + 1;

    let dayQueryDoneCounter = 0;

    for (let i = 1; i <= numOfDays; i += 1) {
      const currentDate = new Date(result2.rows[0].start_date.valueOf());
      currentDate.setDate(currentDate.getDate() + i - 1);
      const dayQueryArr = [result2.rows[0].id, i, currentDate];
      pool.query('INSERT INTO day (trip_id, day_num, date) VALUES ($1, $2, $3) RETURNING *', dayQueryArr)
        .then((result3) => {
          pool.query(`UPDATE tempActivity SET day_id='${result3.rows[0].id}' WHERE day_id=${oldDayIdArr[i - 1]}`).then(() => {
            pool.query(`INSERT INTO activity (day_id, category_id, details, start_time, end_time, comments, transport_type, transport_duration) SELECT tempActivity.day_id, tempActivity.category_id, tempActivity.details, tempActivity.start_time, tempActivity.end_time, tempActivity.comments, tempActivity.transport_type, tempActivity.transport_duration FROM tempActivity INNER JOIN day ON tempActivity.day_id = day.id WHERE day.id = ${result3.rows[0].id}`).catch((error5) => {
              console.log('insert activity table query error', error5);
              res.status(400).send('Sorry, there is an error.');
            });
          });
        }).catch((error4) => {
          console.log('insert activity table query error', error4);
          res.status(400).send('Sorry, there is an error.');
        });
      dayQueryDoneCounter += 1;
    }
    if (dayQueryDoneCounter === numOfDays) {
      res.redirect(`/trip/${result2.rows[0].id}`);
      return pool.query('DROP TABLE tempActivity, tempDay');
    }
  })
    .catch((error) => {
      console.log('Update trip error', error);
      res.status(400).send('Sorry, there is an error.');
    });
});

app.delete('/trip/:id/delete', (req, res) => {
  const tripId = req.params.id;
  pool.query(`DELETE FROM day WHERE trip_id=${tripId}`).then(() => {
    pool.query(`DELETE FROM trip WHERE id=${tripId}`).then(() => {
      res.redirect('/user-dashboard');
    }).catch((error) => {
      console.log('delete trip query error', error);
      res.status(400).send('Sorry, there is an error.');
    }); });
});

app.get('/trip/:id', (req, res) => {
  if (req.isUserLoggedIn === false) {
    res.status(403).send('sorry you are not logged in');
    return;
  }
  // extract loggedInHash and userId from request cookies
  const { loggedInHash, userId } = req.cookies;
  // create new SHA object
  const shaObj3 = new jsSHA('SHA-512', 'TEXT', { encoding: 'UTF8' });
  // reconstruct the hashed cookie string
  const unhashedCookieString = `${userId}-${SALT}`;
  shaObj3.update(unhashedCookieString);
  const hashedCookieString = shaObj3.getHash('HEX');

  // verify if the generated hashed cookie string matches the request cookie value.
  // if hashed value doesn't match, return 403.
  if (hashedCookieString !== loggedInHash) {
    res.status(403).send('please login!');
  }
  else {
    const tripId = Number(req.params.id);
    pool.query(`SELECT day.id AS day_id, day.day_num, day.date, day.trip_id, trip.country, trip.start_date, trip.end_date FROM day INNER JOIN trip ON day.trip_id = trip.id WHERE trip.id=${tripId}`).then((result) => {
      const startDate = new Date(result.rows[0].start_date);
      const endDate = new Date(result.rows[0].end_date);
      const numOfDays = ((endDate - startDate) / (24 * 3600 * 1000)) + 1;
      const tripData = result.rows;
      // console.log('tripData :>> ', tripData);
      pool.query(`SELECT day.id AS day_id, day.trip_id, activity.id, activity.day_id, activity.category_id, details, activity.start_time, activity.end_time, activity.comments, activity.transport_type, activity.transport_duration, category.type FROM day INNER JOIN activity ON day.id = activity.day_id INNER JOIN category ON activity.category_id = category.id WHERE day.trip_id=${tripId}`).then((result2) => {
        const insertedActivitiesData = result2.rows;

        // sort the activities by the start time
        insertedActivitiesData.sort(
          (a, b) => {
            // to make sure sorting is only done within each day
            if (a.day_id === b.day_id) {
              return a.start_time.localeCompare(b.start_time);
            }
            return a.day_id > b.day_id ? 1 : -1;
          },
        );

        res.render('trip', { tripData, numOfDays, insertedActivitiesData });
      }).catch((error2) => {
        console.log('No activity for this trip yet', error2);
        res.status(400).send('Sorry, there is an error.');
      });
    })
      .catch((error) => {
        console.log('Select trip table query error', error);
        res.status(400).send('Sorry, there is an error.');
      });
  }
});

// render a form that will add a new trip
app.get('/new-activity/:dayId', (req, res) => {
  if (req.isUserLoggedIn === false) {
    res.status(403).send('sorry you are not logged in');
    return;
  }
  const dayId = Number(req.params.dayId);
  pool.query(`SELECT day.day_num, day.date, day.trip_id, trip.country FROM day INNER JOIN trip ON day.trip_id = trip.id WHERE day.id=${dayId}`).then((result) => {
    const tripAndDayData = result.rows[0];
    pool.query('SELECT * FROM category').then((result2) => {
      const categoryData = result2.rows;
      res.render('new-activity', { tripAndDayData, dayId, categoryData });
    }).catch((error) => {
      console.log('category query error', error);
      res.status(400).send('Sorry, there is an error.');
    });
  })
    .catch((error) => {
      console.log('new activity query error', error);
      res.status(400).send('Sorry, there is an error.');
    });
});

// accept a POST request to add a new activity
app.post('/new-activity/:dayId', (req, res) => {
  const dayId = Number(req.params.dayId);
  const activityData = req.body;
  const activityInsertQueryArr = [dayId, activityData.category_id, activityData.details, activityData.start_time, activityData.end_time, activityData.comments, activityData.transport_type, activityData.transport_duration];
  pool.query('INSERT INTO activity (day_id, category_id, details, start_time, end_time, comments, transport_type, transport_duration) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *', activityInsertQueryArr)
    .then((result) => {
      console.log(result);
      pool.query(`SELECT day.day_num, day.date, day.trip_id, trip.country FROM day INNER JOIN trip ON day.trip_id = trip.id WHERE day.id=${dayId}`).then((result2) => {
        const tripId = result2.rows[0].trip_id;
        res.redirect(`/trip/${tripId}`);
      }).catch((error) => {
        console.log('day and trip table query error', error);
        res.status(400).send('Sorry, there is an error.');
      });
    })
    .catch((error) => {
      console.log('insert activity table query error', error);
      res.status(400).send('Sorry, there is an error.');
    });
});

// page to display an activity
app.get('/activity/:id', (req, res) => {
  if (req.isUserLoggedIn === false) {
    res.status(403).send('sorry you are not logged in');
    return;
  }
  const activityId = req.params.id;
  pool.query(`SELECT * FROM activity WHERE id=${activityId}`).then((result) => {
    const activityData = result.rows[0];
    pool.query('SELECT * FROM category').then((result2) => {
      const categoryData = result2.rows;
      pool.query(`SELECT day.day_num, day.date, day.trip_id, trip.country FROM day INNER JOIN trip ON day.trip_id = trip.id WHERE day.id=${activityData.day_id}`).then((result3) => {
        const tripAndDayData = result3.rows[0];
        res.render('activity', {
          activityData, categoryData, tripAndDayData, activityId,
        });
      }).catch((error3) => {
        console.log('day and trip query error', error3);
        res.status(400).send('Sorry, there is an error.');
      });
    }).catch((error2) => {
      console.log('category query error', error2);
      res.status(400).send('Sorry, there is an error.');
    });
  }).catch((error) => {
    console.log('select activity query error', error);
    res.status(400).send('Sorry, there is an error.');
  });
});

// render form to edit the activity
app.get('/activity/:id/edit', (req, res) => {
  if (req.isUserLoggedIn === false) {
    res.status(403).send('sorry you are not logged in');
    return;
  }
  const activityId = req.params.id;
  pool.query(`SELECT activity.id AS activity_id, activity.day_id, activity.category_id, activity.details, activity.start_time, activity.end_time, activity.comments, activity.transport_type, activity.transport_duration, day.day_num, day.date, day.trip_id, trip.country FROM activity INNER JOIN day ON activity.day_id = day.id INNER JOIN trip ON day.trip_id = trip.id WHERE activity.id = ${activityId}`).then((result) => {
    const activityData = result.rows[0];
    pool.query('SELECT * FROM category').then((result2) => {
      const categoryData = result2.rows;
      res.render('activity-edit', { activityData, categoryData });
    }).catch((error) => {
      console.log('category query error', error);
      res.status(400).send('Sorry, there is an error.');
    });
  }).catch((error) => {
    console.log('select activity query error', error);
    res.status(400).send('Sorry, there is an error.');
  });
});

app.put('/activity/:id', (req, res) => {
  const activityId = req.params.id;
  const newActivityData = { ...req.body };
  pool.query(`UPDATE activity SET category_id='${newActivityData.category_id}', details='${newActivityData.details}', start_time='${newActivityData.start_time}', end_time='${newActivityData.end_time}', comments='${newActivityData.comments}', transport_type='${newActivityData.transport_type}', transport_duration='${newActivityData.transport_duration}' WHERE id=${activityId} RETURNING *`).then((result) => {
    const activityData = result.rows[0];
    pool.query(`SELECT day.day_num, day.date, day.trip_id, trip.country FROM day INNER JOIN trip ON day.trip_id = trip.id WHERE day.id=${activityData.day_id}`).then((result2) => {
      const tripAndDayData = result2.rows[0];
      res.render('activity', { tripAndDayData, activityData, activityId });
    }).catch((error) => {
      console.log('trip and day query error', error);
      res.status(400).send('Sorry, there is an error.');
    });
  }).catch((error) => {
    console.log('update activity query error', error);
    res.status(400).send('Sorry, there is an error.');
  });
});

app.delete('/activity/:id/delete', (req, res) => {
  const activityId = req.params.id;
  pool.query(`SELECT day.trip_id FROM activity INNER JOIN day ON activity.day_id = day.id WHERE activity.id = ${activityId}`).then((result) => {
    const tripId = result.rows[0].trip_id;
    pool.query(`DELETE FROM activity WHERE id=${activityId}`).then(() => {
      res.redirect(`/trip/${tripId}`);
    });
  }).catch((error) => {
    console.log('select activity query error', error);
    res.status(400).send('Sorry, there is an error.');
  });
});

// render a form to add a buddy
app.get('/add-buddy', (req, res) => {
  if (req.isUserLoggedIn === false) {
    res.status(403).send('sorry you are not logged in');
    return;
  }
  const { userId } = req.cookies;
  pool.query(`SELECT * FROM users WHERE id=${userId}`).then((result) => {
    console.log('result.rows :>> ', result.rows);
    const userData = result.rows[0];
    res.render('add-buddy', { userData });
  }).catch((error) => {
    console.log('select users query error', error);
    res.status(400).send('Sorry, there is an error.');
  });
});

app.post('/add-buddy', (req, res) => {
  const { userId } = req.cookies;
  pool.query(`SELECT * FROM users WHERE name LIKE '${req.body.buddy_user_name}'`).then((result) => {
    if (result.rows[0]) {
      const buddyDataArr = [userId, result.rows[0].id];
      pool.query('INSERT INTO buddy (user_id, buddy_user_id) VALUES ($1, $2) RETURNING *', buddyDataArr).then((result2) => {
        const insertedBuddyData = result2.rows[0];
        console.log('insertedBuddyData :>> ', insertedBuddyData);
        res.redirect('/buddy-dashboard');
      }).catch((error2) => {
        console.log('insert buddy query error', error2);
        res.status(400).send('Sorry, there is an error.');
      });
    } else {
      res.status(400).send('Sorry, there is no such user.');
    }
  }).catch((error) => {
    console.log('select users query error', error);
    res.status(400).send('Sorry, there is an error.');
  });
});

app.get('/buddy-trip/:buddyName/edit', (req, res) => {
  if (req.isUserLoggedIn === false) {
    res.status(403).send('sorry you are not logged in');
    return;
  }
  const { userId } = req.cookies;
  const { buddyName } = req.params;
  let myBuddyTrips = [];
  pool.query(`SELECT trip.country, buddy_trip.trip_id, buddy.user_id, buddy.buddy_user_id, users.name FROM trip INNER JOIN buddy_trip ON trip.id = buddy_trip.trip_id INNER JOIN buddy ON buddy_trip.buddy_id = buddy.buddy_user_id INNER JOIN users ON buddy.buddy_user_id = users.id WHERE buddy.user_id= ${userId} AND users.name = '${buddyName}'`).then((result) => {
    myBuddyTrips = result.rows;
    return pool.query(`SELECT * FROM trip WHERE user_id = ${userId}`);
  }).then((result2) => {
    const allMyTrips = result2.rows;
    const tripsThatBuddyNotIn = allMyTrips.filter(({ country: country1 }) => !myBuddyTrips.some(({ country: country2 }) => country2 === country1));

    res.render('add-buddy-trip', {
      myBuddyTrips, buddyName, allMyTrips, tripsThatBuddyNotIn,
    });
  })
    .catch((error) => {
      console.log('select buddy query error', error);
      res.status(400).send('Sorry, there is an error.');
    });
});

app.put('/buddy-trip/:buddyName', (req, res) => {
  const { buddyName } = req.params;
  const tripToAdd = req.body.country;
  pool.query(`SELECT * FROM users WHERE name='${buddyName}'`).then((result) => {
    console.log('result.rows :>> ', result.rows);
    const buddyTripDataArr = [result.rows[0].id, tripToAdd];
    console.log('buddyTripDataArr :>> ', buddyTripDataArr);
    return pool.query('INSERT INTO buddy_trip (buddy_id, trip_id) VALUES ($1, $2)', buddyTripDataArr);
  }).then(() => {
    res.redirect('/buddy-dashboard');
  })
    .catch((error) => {
      console.log('insert buddy trip query error', error);
      res.status(400).send('Sorry, there is an error.');
    });
});

app.delete('/buddy/:buddyName/delete', (req, res) => {
  const { buddyName } = req.params;
  let buddyUserId = 0;
  pool.query(`SELECT * FROM users where name='${buddyName}'`).then((result) => {
    console.log('result.rows :>> ', result.rows);
    buddyUserId = result.rows[0].id;
    return pool.query(`DELETE FROM buddy_trip WHERE buddy_id=${buddyUserId}`);
  }).then(() => {
    pool.query(`DELETE FROM buddy WHERE buddy_user_id=${buddyUserId}`).then(() => {
      res.redirect('/buddy-dashboard');
    }).catch((error) => {
      console.log('delete buddy query error', error);
      res.status(400).send('Sorry, you dont have the rights to delete this buddy.');
    }); });
});

app.delete('/buddy-trip/:buddyTripId/delete', (req, res) => {
  const { buddyTripId } = req.params;
  pool.query(`DELETE FROM buddy_trip WHERE id=${buddyTripId}`).then(() => {
    res.redirect('/buddy-dashboard');
  }).catch((error) => {
    console.log('delete buddy trip query error', error);
    res.status(400).send('Sorry, there is an error.');
  });
});

app.get('/buddy-dashboard', (req, res) => {
  if (req.isUserLoggedIn === false) {
    res.status(403).send('sorry you are not logged in');
    return;
  }
  const { userId } = req.cookies;

  pool.query(`SELECT users.name, users.photo, buddy.user_id, buddy.buddy_user_id FROM users INNER JOIN buddy ON users.id = buddy.buddy_user_id WHERE buddy.user_id=${userId} UNION
  SELECT users.name, users.photo, buddy.user_id, buddy.buddy_user_id 
  FROM users 
  INNER JOIN buddy 
  ON users.id = buddy.user_id
  WHERE buddy.buddy_user_id=${userId}`).then((result) => {
    const allBuddiesName = [...new Set(result.rows.map((buddy) => buddy.name))];
    const allBuddiesNamePhotos = result.rows;
    return pool.query(`SELECT trip.country, buddy_trip.trip_id, buddy_trip.id AS buddy_trip_id, buddy.user_id, buddy.buddy_user_id, users.name, users.photo FROM trip INNER JOIN buddy_trip ON trip.id = buddy_trip.trip_id INNER JOIN buddy ON buddy_trip.buddy_id = buddy.buddy_user_id INNER JOIN users ON buddy.buddy_user_id = users.id WHERE buddy.user_id =${userId} UNION
    SELECT trip.country, buddy_trip.trip_id, buddy_trip.id AS buddy_trip_id, buddy.user_id, buddy.buddy_user_id, users.name, users.photo 
    FROM trip 
    INNER JOIN buddy_trip 
    ON trip.id = buddy_trip.trip_id 
    INNER JOIN buddy 
    ON buddy_trip.buddy_id = buddy.buddy_user_id 
    INNER JOIN users 
    ON buddy.user_id = users.id 
    WHERE buddy.buddy_user_id=${userId}`).then((result2) => {
      const buddiesWithTripData = result2.rows;
      const buddiesWithTripNames = [...new Set(buddiesWithTripData.map((buddy) => buddy.name))];
      res.render('buddy-dashboard', {
        allBuddiesName, buddiesWithTripData, buddiesWithTripNames, allBuddiesNamePhotos,
      });
    }).catch((error) => {
      console.log('select buddy query error', error);
      res.status(400).send('Sorry, there is an error.');
    }); });
});

// app.get('/user', (req, res) => {
//   res.render('user-dashboard');
// });

app.listen(3002);
