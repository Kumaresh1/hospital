const express= require('express')
const router = express.Router()
const mongoose=require('mongoose')

const Profile = require("../models/products")
router.get('/', (req, res, next)=>
{
    Profile.find()
    .select('name age _id')
    .exec()
    .then(docs =>{
        const response = {
            count: docs.length,
            products: docs.map(doc =>{
                return {
                    name:doc.name,
                    age: doc.age,
                    _id:doc.id,
                    request: {
                        type: "GET",
                        url: "http://localhost:3000/product/"+doc._id
                    }
                }
            })
        }
        console.log(docs)
        res.status(200).json(response)
    })
    .catch(err => {
        console.log(err)
        res.status(500).json({
            error:err
        })
    })
})

router.post('/', (req, res, next)=>
{
    const person = new Profile({
        _id: new mongoose.Types.ObjectId(),
        name: req.body.name,
        age:req.body.age
    })
    person.save().then(result =>{
        console.log(result)
        res.status(201).json({
            message: 'Handling POST requests to /Govt dashboard',
            createdProfile: result
        })
    })
    .catch(err => {
        console.log(err)
        res.status(500).json({
            error:err
        })
    })
    
})

router.get('/:personId', (req,res,next)=>{
    const id = req.params.personId
    Profile.findById(id)
    .exec()
    .then(doc => {
        console.log("From database",doc)
        if(doc){
            res.status(200).json(doc)
        }
        else{
            res.status(404).json({message: "No valid entry found for provided id"})
        }
        res.status(200).json(doc)
    })
    .catch(err => {
        console.log(err)
        res.status(500).json({error:err})
    }) 
})

router.patch('/:personId', (err,req,res,next)=>{
    const id = req.params.productsId
    const updateOps ={}
    for(const ops of req.body)
    {
        updateOps[ops.propName] = ops.value
    }
    Product.update({ _id:id}, { $set : updateOps})
    .exec()
    .then( result=> {
        console.log(result)
        res.status(200).json(result)
    })
    .catch(err => {
        console.log(err)
        res.status(500).json({
            error:err
        })
    })  
})

router.delete('/:personId', (req,res,next)=>{
    const id=req.params.personId
    Profile.findByIdAndDelete({ _id:id})
    .exec()
    .then( result => {
        res.status(200).json(result)
    })
    .catch(err => {
        console.log(err)
        res.status(500).json({
            error:err
        })
    })    
})
module.exports = router;