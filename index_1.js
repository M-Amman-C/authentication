//Authenticate using passport

import env from "dotenv";
env.config();
import express from "express";
import bodyParser from"body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import passportLocal from 'passport-local';
import session from "express-session";

const db = new pg.Client({
    user: process.env.POSTGRESUSER,
    host: process.env.POSTGRESHOST,
    database: process.env.POSTGRESDB,
    password: process.env.POSTGRESPASSWD,
    port: 5432
});

const saltRounds = 10;

const app = express();
const port = 3000;

let currentUserId;

app.use(bodyParser.urlencoded({extended: true}));
app.set('view engine', 'ejs');
app.use(express.static("public"));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(passport.authenticate("session"));

db.connect();

//----------------------------------------------------------------PASSPORT STRATERGIES-------------------------------------------------------------------------


const LocalStrategy = passportLocal.Strategy;

passport.use("local-register",new LocalStrategy(async (username,password,cb)=>{
    try{
        const hash_password =  (await db.query("Select password from users WHERE username=$1",[username])).rows;
        if(hash_password.length>0) {
            return cb(null,false, {message: "Email already Taken"});
        } else{
            bcrypt.hash(password,saltRounds,(err,hash)=>{
                if (err) {
                    return cb(err);
                } else{
                    db.query("INSERT INTO users(username,password) VALUES($1,$2);",[username,hash]);
                    return cb(null,true);
                }
            });
        }
    } catch(err){
      return cb(err);
    }
  }));

passport.use("local-login",new LocalStrategy(async (username,password,cb)=>{
    try{
        const hash_password =  (await db.query("Select * from users WHERE username=$1",[username])).rows;
        if(hash_password.length==0) {return cb(null,false, {message: "User name or password is incorrect"});}
        bcrypt.compare(password,hash_password[0].password,(err,result)=>{
            if (err) {return cb(err);}
            if (result==false){return cb(null, false, { message: 'User name or password is incorrect' });}
            else{
                currentUserId = Number(hash_password[0].id);
                return cb(null,result);
            }
        });
    } catch(err){
    return cb(err);
    }
}));



passport.serializeUser((user,cb)=>{
    process.nextTick(()=>{
        cb(null, {id: user.id, username: user.username});
    });
})

passport.deserializeUser((user,cb)=>{
    process.nextTick(()=>{
        cb(null, user);
    });
})

//----------------------------------------------------------------ROUTES-------------------------------------------------------------------------

app.get("/", (req, res)=> {
    res.render("home")
});
 
app.get("/login", (req, res)=> {
    res.render("login");
});
 
app.get("/register", (req, res)=> {
    res.render("register")
});

app.get("/logout", (req, res)=>{
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
      });
});

app.post("/login", passport.authenticate("local-login", {
    successRedirect: '/secrets',
    failureRedirect: '/login'
})
);

app.post("/register",passport.authenticate("local-register", {
    successRedirect: '/secrets',  // Redirect to secrets page on successful registration
    failureRedirect: '/register'   // Redirect back to the registration page if there is an error
  })
);

app.get("/secrets", (req, res)=> {
    if(req.isAuthenticated()) {
        res.render("secrets");
    }else {
        res.redirect("/login")
    }
});

app.listen(port,()=>{
    console.log("Server Running on port "+port);
});