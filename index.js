import express from "express";
import bodyParser from "body-parser";
import { fileURLToPath, pathToFileURL } from "url";
import dotenv from "dotenv";
import passport from "passport";
import { dirname } from "path";
import session from "express-session";
import pg from "pg";
import bcrypt from "bcrypt";
import { Strategy } from "passport-local";
import flash from "connect-flash";
import GoogleStrategy from "passport-google-oauth2";
import FacebookStrategy from "passport-facebook";
import TwitterStrategy from "passport-twitter";
import OpenIDConnectStrategy from "passport-openidconnect";

dotenv.config();
const app = express();
const dircname = dirname(fileURLToPath(import.meta.url));
const app_server = process.env.port || 3000;

//dataabase config
const db = new pg.Client({
  user: process.env.DATABASE_USER,
  host: process.env.DATABASE_HOST,
  database: process.env.DATABASE_NAME,
  password: process.env.DATABASE_PASSWORD,
  port: process.env.DATABASE_PORT,
});

db.connect();

//=========================Middleware===========================
app.use(express.json()); 
app.use(bodyParser.urlencoded({ extended: true })); //to read url encoded values
app.use(  //express session manager setup
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true },
  })
);

app.use(flash()); //flash service

app.use((req, res, next) => { //flash message setup
  res.locals.success_message = req.flash("success");
  res.locals.error_message = req.flash("error");
  next();
});

app.use(passport.initialize()); //initialize passport service for authentication
app.use(passport.session());

//===============================GET ROUTES======================
//landing page
app.get("/", (req, res) => {
  res.render(dircname + "/views/login.ejs", {
    page: "login",
  });
});

//login page
app.get("/login", async (req, res) => {
  var givenpage = req.params.id;
  res.render(dircname + "/views/login.ejs", {
    page: "login",
  });
});

//createaccount page
app.get("/createaccount", async (req, res) => {
  res.render(dircname + "/views/login.ejs", {
    page: "createaccount",
  });
});

//home page
app.get("/home", isAuthenticated, (req, res) => {
  res.render(dircname + "/views/hello.ejs", {
    data: JSON.stringify(req.user),
  });
});

app.get("/privacypolicy", (req, res) => {
  res.render(dircname + "/views/privacypolicy.ejs", {});
});

//============================================OAUTH GROUP

//google strategy
app.get(
  "/auth/google",
  passport.authenticate("googlestrategy", {
    scope: ["profile", "email"],
  })
);

//google callback
app.get(
  "/auth/google/callback",
  passport.authenticate("googlestrategy", {
    failureRedirect: "/login",
    failureFlash: true,
  }),
  (req, res) => {
    console.log(req.user);
    // Redirect to the dashboard or user details page after successful login
    res.render(dircname + "/views/hello.ejs", {
      data: JSON.stringify(req.user),
    });
  }
);

//facebook strategy
app.get(
  "/auth/facebook",
  passport.authenticate("facebookstrategy", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/facebook/callback",
  passport.authenticate("facebookstrategy", {
    failureRedirect: "/login",
    failureFlash: true,
  }),
  (req, res) => {
    res.render(dircname + "/views/hello.ejs", {
      data: JSON.stringify(req.user),
    });
  }
);

//twitter strategy
app.get(
  "/auth/twitter",
  passport.authenticate("twitterstrategy", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/twitter/callback",
  passport.authenticate("twitterstrategy", {
    failureRedirect: "/login",
    failureFlash: true,
  }),
  (req, res) => {
    res.render(dircname + "/views/hello.ejs", {
      data: JSON.stringify(req.user),
    });
  }
);

//linkedin strategy
app.get(
  "/auth/linkedin",
  passport.authenticate("linkedinstrategy", {
    scope: ["openid", "profile", "email"],
  })
);

app.get(
  "/auth/linkedin/callback",
  passport.authenticate("linkedinstrategy", {
    failureRedirect: "/login",
    failureFlash: true,
  }),
  (req, res) => {
    res.render(dircname + "/views/hello.ejs", {
      data: JSON.stringify(req.user),
    });
  }
);

//======================================POST ROUTES======

//handle login using passport local strategy
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/home",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

//handle create account using passport login strategy
app.post("/createaccount", async (req, res) => {
  const response = await createaccount(req.body);

  if (response.success) {
    req.login(response.user, (err) => {
      if (err) {
        console.log("error logging in");
        req.flash("error", "Error logging in try cred here");
        res.redirect("/login");
      }
      req.flash("success", response.message);
      res.redirect("/home");
    });
  } else {
    req.flash("error", response.message);
    res.redirect("/createaccount");
  }
});

//app server listener
app.listen(app_server, () => {
  console.log(`Listening app on server port ${app_server}`);
});



/***********************************************FUNCTIONS************************************* */
//Check isAuthenticated
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next(); // If user is authenticated, move to the next middleware/route
  }
  // If user is not authenticated, redirect to the login page or another page
  res.redirect("/login");
}

//to find if user already exists
async function finduser(username) {
  try {
    const user = await db.query(`select * from users where username=$1`, [
      username,
    ]);
    if (user.rows.length > 0) {
      return {
        success: true,
        message: "userfound",
        user: user.rows[0],
      };
    } else {
      return {
        success: false,
        message: "user not found",
      };
    }
  } catch (error) {
    return {
      success: false,
      err: error,
    };
  }
}

//to find by id if user already exists
async function finduserbyid(id) {
  try {
    const user = await db.query(`select * from users where id=$1`, [id]);
    if (user.rows.length > 0) {
      return {
        success: true,
        message: "userfound",
        user: user.rows[0],
      };
    } else {
      return {
        success: false,
        message: "user not found",
      };
    }
  } catch (error) {
    return {
      success: false,
      err: error,
    };
  }
}

function validatePassword(password) {
    // 1. At least 8 characters
    // 2. At least one uppercase letter
    // 3. At least one special character
    const regex = /^(?=.*[A-Z])(?=.*[\W_])(?=.{8,})/;

    // Test the password against the regular expression
    if (regex.test(password)) {
        console.log("Password is valid!");
        return {success:true,message:"Password is valid!"};
    } else {
        console.log("Password must have at least 8 characters, one uppercase letter, and one special character.");
        return {success:false, message:"Password must have at least 8 characters, one uppercase letter, and one special character."};
    }
}

function validateEmail(email) {
    //Should be in abc@gmail.com format
    const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email);  // Returns true if email matches the pattern, false otherwise
  }

//Function to createaccount
async function createaccount(userdetails) {
  try {
    const user = await finduser(userdetails.username);

    if (user && user.success) {
      return { success: false, message: "user already exists" };
    } else {
        const validemailformat= validateEmail(userdetails.username);
        if(validemailformat){
        const validatepasswordstatus=validatePassword(userdetails.password);
        if(validatepasswordstatus.success){
      if (userdetails.password === userdetails.confirmpassword) {
        const hash = await bcrypt.hash(userdetails.password, 10);
        if (typeof hash === "string" && hash.trim() !== "") {
          const userCreated = await db.query(
            `insert into users(username,password,data)values($1,$2,$3) RETURNING *`,
            [userdetails.username, hash, userdetails.data]
          );
          return {
            success: true,
            message: "created user successfully",
            user: userCreated.rows[0],
          };
        } else {
          return { success: false, message: "error hashing" };
        }
      } else {
        return { success: false, message: "password didn't match" };
      }
    }else{
        return {success:false, message:validatepasswordstatus.message}
    }
}else{
    return { success: false, message: "enter valid email \"abc@gmail.com\"" };
}
    }
  } catch (error) {
    console.log("error occured: " + error);
    return { success: false, message: "couldn't create a user", error: error };
  }
}

//function to handleStrategyAuth

async function handleuser(profile, done) {
  try {
    // Check if the user already exists by Google ID
    let user = await finduser(profile.emails[0].value);
    if (user.success) {
      console.log("User already exists" + JSON.stringify(user));
      return done(null, user.user); // User already exists, so just return the user
    } else {
      // If user doesn't exist, create a new user
      const newuser = await createaccount({
        username: profile.emails[0].value,
        password: "auth@123", // Default password for  login
        confirmpassword: "auth@123",
        data: profile,
      });

      if (newuser.success) {
        console.log("New user created successfully");
        return done(null, newuser.user); // Return newly created user
      } else {
        console.log("Error creating user:", newuser.message);
        return done(null, false, { message: newuser.message }); // Return an error if user creation fails
      }
    }
  } catch (err) {
    console.log("Error:", err);
    return done(err); // Call done with the error if something goes wrong
  }
}

/****************************PASSPORT STRATEGIES**************************************** */

//local strategy
passport.use(
  "local",
  new Strategy(async (username, password, done) => {
    const user = await finduser(username);
    if (user.success) {
      const result = await bcrypt.compare(password, user.user.password);
      if (result) {
        return done(null, user.user);
      } else {
        return done(null, false, { message: "incorrect password" });
      }
    } else {
      return done(null, false, { message: "User not present" });
    }
  })
);

//google strategy
passport.use(
  "googlestrategy",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      scope: ["email", "profile"],
    },
    async (accessToken, refreshToken, profile, done) => {
      handleuser(profile, done);
    }
  )
);

//facebook strategy
passport.use(
  "facebookstrategy",
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
      callbackURL: process.env.FACEBOOK_CALLBACK_URL,
      scope: ["profile", "email"],
    },
    async (accessToken, refreshToken, profile, done) => {
      handleuser(profile, done);
    }
  )
);

//twitter strategy
passport.use(
  "twitterstrategy",
  new TwitterStrategy(
    {
      consumerKey: process.env.TWITTER_CONSUMER_KEY,
      consumerSecret: process.env.TWITTER_CONSUMER_SECRET,
      callbackURL: process.env.TWITTER_CALLBACK_URL,
      includeEmail: true,
      scope: ["profile", "email"],
    },
    async (token, tokenSecret, profile, done) => {
      console.log(profile);
      handleuser(profile, done);
    }
  )
);

//linkedin strategy
passport.use(
  "linkedinstrategy",
  new OpenIDConnectStrategy(
    {
      issuer: "https://www.linkedin.com/oauth/v2",
      authorizationURL: "https://www.linkedin.com/oauth/v2/authorization",
      tokenURL: "https://www.linkedin.com/oauth/v2/accessToken",
      userInfoURL: "https://api.linkedin.com/v2/me",
      clientID: process.env.LINKEDIN_CLIENT_ID,
      clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
      callbackURL: process.env.LINKEDIN_CALLBACK_URL,
      scope: ["openid", "profile", "email"],
      response_type: "code",
      state: true,
      skipIssuerCheck: true, // Disable the issuer check
      passReqToCallback: true,
    },
    async (issuer, sub, profile, accessToken, refreshToken, done) => {
      console.log(profile);
      //This strategy authentication is still in progress as linked has changes to version 2 i am trying to figureout why it doesn't respond but throws 
      // issuer doesnt send token as required 
    }
  )
);

//serializeuser after authentication
passport.serializeUser((user, done) => {
  done(null, user.id);
});

//deserializeuser after authentication
passport.deserializeUser(async (id, done) => {
  try {
    const user = await finduserbyid(id);
    if (user) {
      done(null, user.user);
    } else {
      done(null, false);
    }
  } catch (error) {
    console.error("Error deserializing user:", error);
    done(error, false);
  }
});
