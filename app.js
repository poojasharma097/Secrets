//jshint esversion:6

const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const encrypt = require('mongoose-field-encryption').fieldEncryption;
const md5 = require('md5');
const bcrypt = require('bcrypt');
const saltRounds = 10;
require('dotenv').config();
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const { request } = require('http');
const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));
app.use(session({
    secret: "Our little secret",
    resave: false,
    saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secrets: {
        type: [{ 
            type: String
        }],
        default: []
    }
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// userSchema.plugin(encrypt,{
//     fields: ["password"],
//     secret: process.env.SECRET,
//     saltGenerator: function (secret) {
//         return "1234567890123456"; 
//     },
// });

const User = mongoose.model("User",userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
    done(null, user);
});
passport.deserializeUser(function(user, done) {
    done(null, user);
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res){
    res.render("home");
});

app.get("/register",function(req,res){
    res.render("register");
});

app.get("/login",function(req,res){
    res.render("login");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ["profile"] }));

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
});

app.get("/secrets",function(req,res){
    User.find({"secrets.0" : {"$exists": true}})
    .then((doc) => {
        // console.log(doc);
        if (doc)
        {
            res.render("secrets", {userWithSecrets: doc});
        }
    })
    .catch((err) => {console.log(err);});
});

app.get("/logout", (req, res) => {
    req.logout(req.user, err => {
      if(err) return next(err);
      res.redirect("/");
    });
});

app.get("/submit",function(req,res){
    if (req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login");
    }
});

app.post("/register",function(req,res){
    User.register({username: req.body.username}, req.body.password, function(err, user) {
        if (err) {
            console.log(err);
            res.redirect("/"); 
        }
        else
        {
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login",function(req,res){
    const user = new User({
        email: req.body.username,
        passport: req.body.password
    });
    req.login(user,function(err){
        if (err)
        {
            console.log(err);
        }
        else
        {
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    }) 
});

app.post("/submit",function(req,res){
    const submittedSecret = req.body.secret;
    User.findOne({_id: req.user._id})
    .then(
        (secretList) => {
            secretList.secrets.push(submittedSecret);
            secretList.save();
            res.redirect("/secrets");
        }
    )
    .catch((err) => {console.log(err);});
})

// app.post("/register",function(req,res){
//     bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
//         // Store hash in your password DB.
//         const newUser = new User({
//             email: req.body.username,
//             password: hash
//         });
//         newUser.save()
//         .then((doc) => {res.render("secrets");})
//         .catch((err) => {res.send(err);});
//     });
// });
// app.post("/login",function(req,res){
//     User.findOne({email: req.body.username})
//     .then((foundUser) => {
//         bcrypt.compare(req.body.password, foundUser.password, function(err, result) {
//             if (result === true)
//             {
//                 res.render("secrets");
//             }
//         });
//     })
//     .catch((err) => {res.send(err);});
// });

app.listen("4000", function(){
    console.log("Server is running on port 4000.");
})