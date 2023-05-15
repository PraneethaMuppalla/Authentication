import UserModel  from "../models/User.js";
import bcrypt from 'bcrypt'
import jwt from "jsonwebtoken";

class UserController{
static userRegistration = async(req,res)=>{
    const {name,email,password,password_confirmation} = req.body
    const user = await UserModel.findOne({email:email})
    if(user){
        res.status(400).send({"status":"failed","error_msg":"Email already exists"})
    }else {
        if (name && email && password && password_confirmation ){
            if (password === password_confirmation){
               try{
                const salt = await bcrypt.genSalt(10)
                const hashedPassword =await bcrypt.hash(password,salt)
                const newUser = new UserModel({
                    name,
                    email,
                    password:hashedPassword,
                })
                await newUser.save()
                const saved_user = await UserModel.findOne({email:email})
                // jwt token
                
                const jwtToken = jwt.sign({userId:saved_user._id},process.env.JWT_SECRET_KEY,
                    {expiresIn:"15d"})
                res.status(201).send({"status":"SUCCESS","message":"Registered Successfully","jwt_token":jwtToken})
               }catch (error) {
                console.log(error)
                res.status(400).send({"status":"failed","error_msg":"Unable to Register"})

               }

            }else{
                res.status(400).send({"status":"failed","error_msg":"Passwords doesn't match"})
            }
        }
        else{
            res.status(400).send({"status":"failed","error_msg":"All fields are required"})  
        }
    }
}

static userLogin = async(req,res)=>{
    try{
        const {email,password} = req.body
        if (email && password){
            const user =await UserModel.findOne({email:email})  
            if (user != null){
                const isPasswordMatched = await bcrypt.compare(password,user.password)
                if ((user.email === email) && isPasswordMatched){
                    // GENERATE JWT TOKEN
                    const jwtToken = jwt.sign({userId:user._id},process.env.JWT_SECRET_KEY,
                        {expiresIn:"15d"})
                    res.status(200).send({"status":"SUCCESS","message":"Login SUCCESS","jwt_token":jwtToken})  


                }else{
                    res.status(400).send({"status":"failed","error_msg":"Email or password is not valid"})    
                }

            }else{
                res.status(400).send({"status":"failed","error_msg":"You are not a Registered user"})  
            }

        }else{
            res.status(400).send({"status":"failed","error_msg":"All fields are required"})  
        }

    }catch(error){
     console.log(error)
     res.send({"status":"failed","error_msg":"Unable to Login"})  
    }
}
static changeUserPassword = async(req,res)=>{
    const {password,password_confirmation} = req.body
    if (password && password_confirmation){
        if (password !== password_confirmation){
            res.status(400).send({"status":"failed","error_msg":"New Password and Confirm New Password doesn't match"})  
        }else {
            const salt = await bcrypt.genSalt(10)
            const hashedPassword =await bcrypt.hash(password,salt)
            await UserModel.findByIdAndUpdate(req.user._id,{$set:{password:hashedPassword}})
            res.status(200).send({"status":"SUCCESS","message":"Password Changed Successfully",})    
        }

    }else{
        res.status(400).send({"status":"failed","error_msg":"All fields are required"})  
    }
}

static loggedUser = async(req,res)=>{
    res.send({"user":req.user})
}

static resetPasswordByUsingEmail = async(req,res)=>{ 
    const {email} = req.body
    if(email){
 const user = await UserModel.findOne({email:email})
 
 if (user){
    const secretKey = user._id + process.env.JWT_SECRET_KEY
    const jwtToken = jwt.sign({userId:user._id},secretKey,
        {expiresIn:"10m"})
        const link = `http://127.0.0.1:3000/api/user/reset/${user._id}/${jwtToken}`
        console.log(link)
        res.status(200).send({"status":"SUCCESS","message":"Password reset email sent. Please check your email","jwt_token":jwtToken})  

 }else{
    res.status(400).send({"status":"failed","error_msg":"Email doesn't exists"}) 
 }
    }else{
        res.status(400).send({"status":"failed","error_msg":"All fields are required"}) 
    }
 }
 static userPasswordReset = async (req, res) => {
    const { password, password_confirmation } = req.body;
    const { id, jwtToken } = req.params;

    const user = await UserModel.findById(id);
    const new_secret = user._id + process.env.JWT_SECRET_KEY;

    try {
      jwt.verify(jwtToken, new_secret);
      if (password && password_confirmation) {
        if (password !== password_confirmation) {
          res.status(400).send({ status: 'failed', error_msg: "New Password and Confirm New Password don't match" });
        } else {
          const salt = await bcrypt.genSalt(10);
          const hashedPassword = await bcrypt.hash(password, salt);
          await UserModel.findByIdAndUpdate(id, { $set: { password: hashedPassword } });
          res.status(200).send({ status: 'SUCCESS', message: 'Password Reset Successfully' });
        }
      } else {
        res.status(400).send({ status: 'failed', error_msg: 'All fields are required' });
      }
    } catch (error) {
      console.log(error);
      res.status(400).send({ status: 'failed', error_msg: 'Invalid or expired token' });
    }
  }
}

export default UserController;