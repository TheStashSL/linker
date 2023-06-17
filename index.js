// Dependencies
const express = require('express');
const passport = require('passport');
const session = require('express-session');
const DiscordStrategy = require('passport-discord').Strategy;
const SteamStrategy = require('passport-steam').Strategy;
const bodyParser = require('body-parser');
const mariadb = require('mariadb');
const path = require('path');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

// Configuration
const config = require('./config.json');

// Express app
const app = express();

// Database connection
const pool = mariadb.createPool(config.database);
pool.getConnection()
  .then(conn => {
    console.log('Connected to database');
    conn.release();
  })
  .catch(err => {
    console.log('Error connecting to database');
  });

// Passport session setup
passport.serializeUser(function (user, done) {
  done(null, user);
});

passport.deserializeUser(function (obj, done) {
  done(null, obj);
});

// Discord authentication
passport.use(new DiscordStrategy({
  clientID: config.discord.clientID,
  clientSecret: config.discord.clientSecret,
  callbackURL: config.discord.callbackURL,
  scope: config.discord.scope
}, function (accessToken, refreshToken, profile, done) {
  process.nextTick(function () {
    return done(null, profile);
  });
}));

// Steam authentication
passport.use(new SteamStrategy({
  returnURL: config.steam.returnURL,
  realm: config.steam.realm,
  apiKey: config.steam.apiKey
}, function (identifier, profile, done) {
  process.nextTick(function () {
    return done(null, profile);
  });
}));

// Express setup
app.use(session({
  secret: config.session.secret,
  resave: false,
  saveUninitialized: false
}));
app.use(cookieParser(config.cookieSecret));
app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Routes
app.get('/', function (req, res) {
  res.redirect('/login/discord');
});

app.get('/login/discord', passport.authenticate('discord'));

app.get('/login/steam', passport.authenticate('steam'));

app.get('/auth/discord/callback', passport.authenticate('discord', {
  failureRedirect: '/login/discord'
}), function (req, res) {
  var discordID = req.session.passport.user.id; // Discord ID from the Discord authentication
  console.log(`Discord ID: ${discordID}`);

  // Encrypt the Discord ID
  var encryptedDiscordID = encryptDiscordID(discordID);

  // Set the encrypted Discord ID in a signed cookie
  res.cookie('discordID', encryptedDiscordID, { signed: true });

  res.redirect('/login/steam');
});

app.get('/auth/steam/callback', passport.authenticate('steam', {
  failureRedirect: '/login/steam'
}), function (req, res) {
  var encryptedDiscordID = req.signedCookies.discordID; // Retrieve the encrypted Discord ID from the signed cookie
  var discordID = decryptDiscordID(encryptedDiscordID); // Decrypt the Discord ID
  var steamID = req.user._json.steamid; // Steam ID from the Steam authentication

  // Check if either Discord or Steam ID already exists in the database
  pool.getConnection()
    .then(conn => {
      conn.query("SELECT * FROM AccountLinks WHERE discord_id = ? OR steam_id = ?", [discordID, steamID])
        .then(rows => {
          if (rows.length > 0) {
            // IDs already exist, inform the user
            conn.release();
            res.send('Discord or Steam IDs already exist in the database.');
          } else {
            // IDs don't exist, insert into the database
            conn.query("INSERT INTO AccountLinks (discord_id, steam_id) VALUES (?, ?)", [discordID, steamID])
              .then(() => {
                console.log('User added to database');
                conn.release();
                res.redirect('/done');
              })
              .catch(err => {
                console.log('Error adding user to database');
                conn.release();
                res.send('Error adding user to the database.');
              });
          }
        })
        .catch(err => {
          console.log(`Error querying the database: ${err}`);
          conn.release();
          res.send('Error querying the database.');
        });
    })
    .catch(err => {
      console.log('Error connecting to database');
      res.send('Error connecting to the database.');
    });
});

app.get('/done', function (req, res) {
  res.send('Your accounts were added to the database! You can now close this page!');
});

app.listen(config.port, function () {
  console.log('Listening on port ' + config.port);
});

// Helper function to encrypt the Discord ID
function encryptDiscordID(discordID) {
  const algorithm = 'aes-256-cbc';
  const key = crypto.scryptSync(config.encryptionKey, 'salt', 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(discordID, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + encrypted;
}

// Helper function to decrypt the Discord ID
function decryptDiscordID(encryptedDiscordID) {
  const algorithm = 'aes-256-cbc';
  const key = crypto.scryptSync(config.encryptionKey, 'salt', 32);
  const iv = Buffer.from(encryptedDiscordID.slice(0, 32), 'hex');
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decrypted = decipher.update(encryptedDiscordID.slice(32), 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}
