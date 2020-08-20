//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");



const app = express();


app.use(express.static("public"));
app.set('view engine',ejs);
app.use(bodyParser.urlencoded({
    extended:true
}));

app.use(session({
    secret:"thisismysecret.",
    resave: false,
    saveUnitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
       email: String,
       password: String,
       googleId: String,
       secret: String

});

//hash and salt users and save to db
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());
 
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

//passport google oauth
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
    res.render("home.ejs");
});
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get("/login", function(req, res){
    res.render("login.ejs");
});
app.get("/register", function(req, res){
    res.render("register.ejs");
});
app.get("/secrets", function(req, res){
    User.find({"secret": {$ne: null}}, function(err, foundUsers){
      if (err){
        console.log(err);
      } else {
        if (foundUsers) {
          res.render("secrets.ejs", {usersWithSecrets: foundUsers});
        }
      }
    });
  });

app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

//Once the user is authenticated and their session gets saved, their user details are saved to req.user.
  // console.log(req.user.id);

  User.findById(req.user.id, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout",function(req,res){
    req.logout();
    res.redirect("/");
});

app.post("/register",function(req,res){
    User.register({username:req.body.username},req.body.password,function(err,user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req,res,function(){
                user.secret="My Secret is...";
                user.save(function(){
                    res.redirect("/secrets");
                })
            })
        }
    })

});

app.post("/login",function(req,res){
    const user = new User({
        username:req.body.username,
        password:req.body.password
    })
    req.login(user,function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    })

});
//TODO



app.listen(process.env.PORT||3000, function(){
    console.log(`Server started on port${process.env.PORT||3000}`);
});

// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;

//only encrypt password
// userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:["password"]});

//bcrypt register
// app.post("/register",function(req,res){
//     //hashes password with bcrypt + 10saltRounds to save to DB
//     bcrypt.hash(req.body.password,saltRounds,function(err,hash){
//         const newUser = new User({
//             email: req.body.username,
//             password:hash
//         })
//         newUser.save(function(err){
//             if(err){
//                 console.log(err);
//             }else{
//                 res.render("secrets.ejs");
//             }
//         })
//     });
// })
// //bcrypt login
// app.post("/login",function(req,res){
//     const username = req.body.username;
//     const password = req.body.password;
//     User.findOne({email:username},function(err,foundUser){
//         if(err){
//             console.log(err);
//         } else{
//             if(foundUser){
//                 bcrypt.compare(password,foundUser.password,function(err,result){
//                     if(result===true){
//                         res.render("secrets.ejs");
//                     }
//                 })
//             }
//         }
//     })
// }