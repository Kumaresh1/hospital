const express = require('express')
const app = express()
const morgan = require('morgan')
const bodyParser = require('body-parser')
const mongoose = require ('mongoose')
const cookieParser = require("cookie-parser");

app.use(cookieParser());


const productRoutes= require('./routes/product')
const userRoutes = require('./routes/user')

/*mongoose.connect('mongodb+srv://Ishanuj99:ywWy2JhnS6kwJ7k@cluster0.v76sp.mongodb.net/myFirstDatabase?retryWrites=true&w=majority',
    { useNewUrlParser: true,
      useUnifiedTopology: true
})*/
mongoose.connect('mongodb+srv://dbmongo19:arisha1234@covidhealthdatabase.6ds4n.mongodb.net/Publicdashboard',
    { useNewUrlParser: true,
      useUnifiedTopology: true,
      useCreateIndex:true
})
.catch(err => console.log(err))

mongoose.Promise= global.Promise

app.use(morgan('dev'))
app.use(express.urlencoded({extended:true}))
app.use(express.json())

app.use((req,res,next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header(
        "Access-Control-Allow-Headers",
        "Origin, X-Requested-With, Content-Type, Accept, Authentication"
    )
    if(req.method === 'OPTIONS') {
        res.header('Access-Control-Allow-Metods', 'PUT,POST,PATCH,DELETE,GET')
        return res.status(200).json({});
    }
    next();
    })

//Routes which should handle requests
app.use('/product', productRoutes)
app.use("/user",userRoutes)

//Handling error requests
app.use((req, res, next)=>{
    const error = new Error("Not Found");
    error.status=400;
    next(error);
})
app.use((error, req, res, next) =>{
    res.status(error.status || 500)
    res.json({
        error: {
            message: error.message
        }
    })
})

module.exports = app