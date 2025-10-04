
import User from "../model/user.model.js";
import bcrypt from "bcryptjs";
import  genToken  from "../config/token.js";
export const signUp =async(req, res) => {
  try {
    let {name,email,password} = req.body;
    let existUser = await User.findOne({email});
    if(existUser){
      return res.status(400).json({message:"User already exist"});
    }
    let hashPassword = await bcrypt.hash(password,10);
    let user = await User.create({name,email,password:hashPassword});
    let token= await genToken(user._id);
    res.cookie("token",token,{httpOnly:true,
      secure:process.env.NODE_ENVIORNMENT==="production"?true:false,
      sameSite:"strict",
      maxAge:7*24*60*60*1000
    });
    return res.status(201).json({message:"User created successfully",user});
  } catch (error) {
    return res.status(500).json({message:"Error in user creation",error});
  }
}

export const login = async(req, res) => {
  try {
    let {email,password} = req.body;
    let user = await User.findOne({email});
    if(!user){
      return res.status(400).json({message:"User does not exist"});
    }   
    let isMatch = await bcrypt.compare(password,user.password);
    if(!isMatch){
      return res.status(400).json({message:"Invalid credentials"});
    }
    let token= await genToken(user._id);
    res.cookie("token",token,{httpOnly:true,
      secure:process.env.NODE_ENVIORNMENT==="production"?true:false,
      sameSite:"strict",      
      maxAge:7*24*60*60*1000
    });
    return res.status(200).json({message:"Login successful",user});
  } catch (error) {
    return res.status(500).json({message:"Error in user login",error});
  }
}

export const logout = (req, res) => {
  try {
    res.clearCookie("token");
    return res.status(200).json({message:"Logout successful"});
  } catch (error) {
    return res.status(500).json({message:"Error in user logout",error});
  }

}