const express = require("express");
const router = express.Router();
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const checkAuth=require("../middleware/check-auth")


const User = require("../models/user");
router.get("/", (req, res, next) => {
    User.find()
        .select('_id UserName password email CreatedDate UpdatedDate Role')
        .exec()
        .then(docs => {
            const response = {
                count: docs.length,
                users: docs.map(doc => {
                    return {
                        UserName:doc.UserName,
                        password: doc.password,
                        email: doc.email,
                        CreatedDate: doc.CreatedDate,
                        UpdatedDate:doc.UpdatedDate,
                        Role: doc.Role,
                        _id: doc._id,
                        request: {
                            type: "GET",
                            url: "http://localhost:2021/users/" + doc._id

                        }
                    };
                })
            };
            res.status(200).json(response);
        })
        .catch(err => {
            console.log(err);
            res.status(500).json({
                error: err
            });
        });
});

router.post("/signup", (req, res, next) => {
    User.find({ email: req.body.email })
        .exec()
        .then(user => {
            if (user.length >= 1) {
                return res.status(409).json({
                    message: "Mail exists"
                });
            } else {
                bcrypt.hash(req.body.password, 10, (err, hash) => {
                    if (err) {
                        return res.status(500).json({
                            error: err
                        });
                    } else {
                        const user = new User({
                            _id: new mongoose.Types.ObjectId(),
                            email: req.body.email,
                            password: hash,
                            UserName:  req.body.UserName,
                            Role:req.body.Role,
                            CreatedDate: new Date().toISOString(),
                            UpdatedDate:new Date().toISOString()

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
//to find user by particular Id
router.get("/:userId", (req, res, next) => {
    const id = req.params.userId;
    User.findById(id)
        .select('_id UserName password email CreatedDate UpdatedDate Role')
        .exec()
        .then(doc => {
            if (doc) {
                res.status(200).json({
                    user: doc,
                    request: {
                        type: 'GET',
                        url: 'http://localhost:2021/users',

                    }
                });
            } else {
                res
                    .status(404)
                    .json({ message: "No valid entry found for provided ID" });
            }
        })
        .catch(err => {
            console.log(err);
            res.status(500).json({ error: err });
        });
});
//sort
router.get('/users/filter', async(req, res, next) => {
    const role = req.params.Role;

    const match ={}
    const sort={}
     if(req.query.role){
          match.role=req.query.role==='true'
      }
      if(req.query.sortBy){
        const str = req.query.sortBy.split(':')
        sort[str[0]] = str[1] === 'desc' ? -1:1
    }
    try {
         const users = await Users.find({role:req.params.Role})
        await req.User.populate({
            path:'users',
            match,
            options:{
                limit:parseInt(req.query.limit),
                skip:parseInt(req.query.skip),

                  sort:{
                      Role:admin||supetadmin||employee,
                      CreatedDate:1,


                  }
            }
        }).execPopulate();
        res.status(200).send(req.user.users)
    }catch(e) {
        res.status(400).send(e.message)
    }

  });


router.post("/login", (req, res, next) => {
    User.find({ email: req.body.email })
        .exec()
        .then(user => {
            if (user.length < 1) {
                return res.status(401).json({
                    message: "Auth failed"
                });
            }
            bcrypt.compare(req.body.password, user[0].password, (err, result) => {
                if (err) {
                    return res.status(401).json({
                        message: "Auth failed"
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
                    return res.status(200).json({
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
router.patch("/:userId", checkAuth,(req, res, next) => {
    const id = req.params.userId;
    const updateOps = {};

    for (const ops of req.body) {
        updateOps[ops.propName] = ops.value;
    }
    Product.update({ _id: id }, { $set: updateOps })
        .exec()
        .then(result => {

            res.status(200).json({
                message: 'User updated',
                UpdatedDate:new Date().toISOString()

                
            });
        })
        .catch(err => {
            console.log(err);
            res.status(500).json({
                error: err
            });
        });
});


module.exports = router; 
