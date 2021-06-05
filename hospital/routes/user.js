const express = require("express");
const router = express.Router();
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const User = require("../models/user");

const cookieParser = require("cookie-parser");

const app = express();
app.use(cookieParser());

router.post("/signup", (req, res, next) => {
  User.find({ Email: req.body.Email })
    .exec()
    .then(user => {
      if (user.length >= 1) {
        return res.status(409).json({
          message: "Mail exists"
        });
      } else {
        bcrypt.hash(req.body.Password, 10, (err, hash) => {
          if (err) {
            return res.status(500).json({
              error: err
            });
          } else {
            const user = new User({
              _id: new mongoose.Types.ObjectId(),
              User_id: req.body.User_id,
              First_Name: req.body.First_Name,
              last_name: req.body.last_name,              
              Email: req.body.Email,
              Password: hash,
              Address:req.body.Address,
              City:req.body.City,
              State:req.body.State,
              Zip:req.body.Zip
            });
            user
              .save()
              .then(result => {
                console.log(result);
                res.status(201).json({
                  message: "User created"
                });
              })
              .catch(err => {
                console.log(err);
                res.status(500).json({
                  error: err
                });
              });
          }
        });
      }
    });
});

router.post("/login", (req, res, next) => {
  User.find({ Email: req.body.Email })
    .exec()
    .then(user => {
      if (user.length < 1) {
        return res.status(401).json({
          message: "Auth failed 1"
        });
      }
    
      bcrypt.compare(req.body.Password, user[0].Password, (err, result) => {
        if (err) {
          return res.status(401).json({
            message: "Auth failed 2"
          });
        }
        if (result) {
          const token = jwt.sign(
            {
              email: user[0].email,
              userId: user[0]._id
            },
            process.env.JWT_KEY,
            {
                expiresIn: "1h"
            }
          );
          
          return res.cookie('authtoken',token,{maxAge:600*600}).status(200).json({
            message: "Auth successful",
            token: token
          });
        }
        res.status(401).json({
          message: "Auth failed"
        });
      });
    })
    .catch(err => {
      console.log(err);
      res.status(500).json({
        error: err
      });
    });
});

router.delete("/:userId", (req, res, next) => {
  User.remove({ _id: req.params.userId })
    .exec()
    .then(result => {
      res.status(200).json({
        message: "User deleted"
      });
    })
    .catch(err => {
      console.log(err);
      res.status(500).json({
        error: err
      });
    });
});

router.post("/logout", (req, res, next) => {
  
  
if(req.cookies.authtoken==undefined){
  return res.json({
    message:"No user is logged in"
  })
}

  res.cookie('authtoken',"",{maxAge:1,
   
  }).json({
  message:"Logout Successful"
});         

});


router.get("/getcookies",(req,res)=>{

  console.log("cookie : ",req.cookies)
  res.json({
    message:req.cookies
  });
});


module.exports = router;