const mongoose = require('mongoose')

const userSchema = mongoose.Schema({
    _id: mongoose.Schema.Types.ObjectId,
    User_id: {type:String, unique:true},
    First_Name: {type: String},
    last_name: {type:String},
    Mobile_No: {type:Number},
    Email: {type:String, 
            unique:true, 
            match:/[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/},
    Password: {type: String},
    Address: {type:String},
    City: {type: String},
    State: {type: String},
    Zip : {type: Number}
},  { collection: 'Publicsignup'}
)

module.exports = mongoose.model('user', userSchema)