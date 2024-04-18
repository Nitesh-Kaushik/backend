import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import {User} from "../models/user.models.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import  jwt  from "jsonwebtoken";

const generateAccessAndRefreshTokens = async(userId) => {
    try{
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return {accessToken, refreshToken}

    }catch(error){
        throw new ApiError(500, "something went wrong while generating refresh and access token")
    }
}

const registerUser = asyncHandler( async (req, res) => {
  // get user detail from frontend

  // validation - not empty

  // check if user already exist: username, email

  // check for images, check for avatar

  // upload them to cloudinary, avatar

  // create user object - create entry in db

  // remove password and refresh token field from response

  // check for user creation 

  // return res

  const {username, fullname, email, password } = req.body

  if([fullname, email, username, password].some((field) => field?.trim() === "")) {
    throw new ApiError(400, "All field are required")
  }

  const existedUser =  await User.findOne({
    $or: [{username}, {email}]
  })


  if (existedUser) {
    throw new ApiError(409, "User with email or password already exists")
  }

  const avatarLocalPath = req.files?.avatar[0]?.path;
  const coverImageLocalPath = req.files?.coverImage[0]?.path;

  if(!avatarLocalPath){
    throw new ApiError(400, "Avatar file is required");
  }

  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);

  if(!avatar){
    throw new ApiError(400, "Avatar file is required")
  }

  const user = User.create({
    fullname,
    avatar: avatar.url,
    coverImage: coverImage?url : "" ,
    email,
    password,
    username: username.toLowerCase
  })


const createdUser = User.findById(user._id).select(
    "-password -refreshToken"
)

if(!createdUser) {
    throw new Error(500, "something went wrong while registring user");
}
return res.status(201).json(
    new ApiResponse(200, createdUser, "User registered successfully")
)
})

const loginUser = asyncHandler( async (req, res) => {
    // req.body -> data
    // username or email
    // find a user
    // password check
    // access and refresh token
    // send cookie


    const {email, username, password} = req.body

    if(!username || !email){
        throw new ApiError(400, "username or password is required")
    }

    const user = await User.findOne({
        $or: [{username} , {email}]
    })

    if (!user) {
        throw new ApiError(404, "User doesn't exist")
    }

    const isPassword = await user.isPasswordCorrect(password)
    
    if (!user) {
        throw new ApiError(401, "Invalid user credentials")
    }

    const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(user._id)

   const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

   const option = {
    httpOnly: true,
    secure: true
   }

   return res.status(200)
        .cookie("accessToken", accessToken, option)
        .cookie("refreshToken", refreshToken, option)
        .json(
            new ApiResponse(
                200,
                {
                    user: loggedInUser, accessToken, refreshToken
                },
                "User logged in successfully"
            )
        )
})

const logoutUser = asyncHandler( async (req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const option = {
        httpOnly: true,
        secure: true
       }
       
    return res.status(200).clearCookie("accessToken", option)   
} )

const refreshAcessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshAcessToken

    if(incomingRefreshToken) {
        throw new ApiError(401, "unauthorized request")
    }

    try {
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)
    
        const user = User.findById(decodedToken?._id)
    
        if(!user) {
            throw new ApiError(401, "Invalid refresh token")
        }
        if(incomingRefreshToken  !== user?.refreshAcessToken) {
            throw new ApiError(401, "Refresh token is expired or used")
        }
    
        const options = {
            httpOnly: true,
            secure: true
        }
    
        const {accessToken, newRefreshToken} = await generateAccessAndRefreshTokens(user._id);
    
        return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(
            new ApiResponse(
                200,
                {accessToken, refreshToken: newRefreshToken},
                "Access token refresh "
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
    }
})

export {registerUser, loginUser, logoutUser, refreshAcessToken}




