const express = require('express');
const app = express();
const morgan = require('morgan');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const path = require('path');
const url = 'mongodb://localhost:27017/Assignment';
mongoose.connect(url,{
    useNewUrlParser: true,
    useUnifiedTopology: true
});
mongoose.Promise = global.Promise;

app.set('view-engine','ejs');


//permissions
app.use((req,res,next)=>{
    req.header("Access-Control-Allow-Origin",'*')
    req.header("Access-Control-Allow-Origin","Origin,Content-Type,Accept,Authentication");//header will contain all this.
    if(req.method === 'OPTIONS'){
        req.header('Access-Control-Allow-Origin','PUT,POST,PATCH,DELETE,GET');
        return res.status(200).json({});
    }
    next();
});

const userRoutes = require('./api/routes/users');

app.use(morgan('dev'));
app.use(bodyParser.urlencoded({extended: false}));
app.use(bodyParser.json());


app.use('/users',userRoutes);
//err handling middleware
app.use((req,res,next)=>{
    const error = new Error("not found");
    res.status(400);
    next(error);
})
app.use((error,req,res,next)=>{
    res.status(error.status || 500);
    res.json({
        error:{
            message: error.message,
        }
    })
})
module.exports = app;