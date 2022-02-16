require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose')

const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')

var FacebookStrategy = require('passport-facebook').Strategy;



// const encrypt = require('mongoose-encryption')
//
// const md5 = require('md5');
//
// const bcrypt = require('bcrypt')
// const saltRounds = 10;

const session = require('express-session')
const passport = require('passport')
const passLocalMongoose = require('passport-local-mongoose')



const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({
  secret: "Our little secret",
  resave: false,
  saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session())


mongoose.connect('mongodb://localhost:27017/userDB')
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String,
});
userSchema.plugin(passLocalMongoose);
userSchema.plugin(findOrCreate);

// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });

const User = new mongoose.model("User", userSchema)

passport.use(User.createStrategy());
passport.serializeUser(function(user, done){
  done(null, user.id);
});
passport.deserializeUser(function(id, done){
  User.findById(id, function(err,user){
    done(err, user);
  });
});



passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.App_ID,
    clientSecret: process.env.App_Secret,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      console.log(profile.id);
      return cb(err, user);
    });
  }
));




app.get('/', function(req,res){
  res.render('home')
})


app.get('/auth/google',
  passport.authenticate("google",{scope: ['profile'] })
);
app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });


  app.get('/auth/facebook',
    passport.authenticate('facebook',{scope: ['email'] }));

  app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login',
  successRedirect:'/secrets'
 }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/');
    });

app.get('/login', function(req,res){
  res.render('login')
})

app.get('/secrets', function(req,res){
  // if (req.isAuthenticated()){
  //   res.render('secrets');
  // }else{
  //   res.redirect('/login')
  // }

  User.find({'secret':{$ne:null}}, function(err, foundUsers){
    if(err){
      console.log(err);
    }else{
      if (foundUsers){
        res.render('secrets', {usersWithSecrets: foundUsers})
      }
    }
  })
})




app.get('/register', function(req,res){
  res.render('register')
})

app.get('/logout', function(req,res){
  req.logout();
  res.redirect('/');
})

app.get('/submit', function(req,res){
  if (req.isAuthenticated()){
    res.render('submit')
  } else {
    res.redirect('/login');

  }
});


app.post('/submit', function(req,res){
  const submitedSecret = req.body.secret;
  console.log(req.user.id);
  User.findById(req.user.id, function(err, foundUser){
    if(err){
      console.log(err);
    }else{
      if (foundUser){
        foundUser.secret = submitedSecret;
        foundUser.save(function(){
          res.redirect('/secrets')
        });
      }
    }
  });
});



app.post('/register', function(req,res){
  User.register({username:req.body.username},req.body.password,function(err,user){
    if (err){
      console.log(err);
      res.redirect('/register');
    }else{
      passport.authenticate('local')(req,res,function(){
        res.redirect('/secrets');
      })
    }
  })
  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   const newUser = new User({
  //     email: req.body.username,
  //     password: hash
  //   });
  //   newUser.save(function(err){
  //     if(err){
  //       res.send(err)
  //     }else{
  //       res.render('secrets')
  //     }
  //   });
  // });



});

app.post('/login', function(req,res){
  const user =  new User({
    username: req.body.username,
    password: req.body.password,
  });
  req.login(user, function(err){
    if(err){
      console.log(err);
    }else{
      passport.authenticate('local')(req,res, function(){
        res.redirect('/Secrets')
      })
    }
  })
//
//     const username =  req.body.username;
//     const password = req.body.password;
//
// User.findOne({email:username}, function(err, foundUser){
//   if(err){
//     console.log(err);
//   }else{
//     if(foundUser){
//       bcrypt.compare( password, foundUser.password, function(err, result) {
//         if (result === true){
//           res.render('secrets')
//
//         }
//       });
//       }
//     }
//   }
// );
});





app.listen(3000, function(){
  console.log("server running on 3000");
});
