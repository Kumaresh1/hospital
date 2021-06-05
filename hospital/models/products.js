const mongoose = require('mongoose')

const profileSchema = mongoose.Schema({
    _id: mongoose.Schema.Types.ObjectId,
    name: {type:String, required:true},
    age: {type: Number, required:true}
})

module.exports = mongoose.model('Profile', profileSchema)