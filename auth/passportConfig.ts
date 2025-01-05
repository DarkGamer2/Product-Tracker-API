import passport from "passport";
import { userInterface } from "../interfaces/interface";
import User from "../models/User";
import bcrypt from "bcryptjs";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import jwt from "jsonwebtoken";

// Local Strategy (for username/password authentication)
passport.use(new LocalStrategy(async (username: string, password: string, done: any) => {
    try {
        const user = await User.findOne({ username });

        if (!user || !user.password) { // Check if user or password is undefined
            return done(null, false, { message: 'Incorrect username or password' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) {
            return done(null, user);
        } else {
            return done(null, false, { message: 'Incorrect password' });
        }
    } catch (err) {
        return done(err);
    }
}));

// JWT Strategy (for JWT-based authentication)
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), // Look for JWT in Authorization header
    secretOrKey: process.env.JWT_SECRET || "your-secret-key", // Secret for signing JWT (you should use a strong secret)
};

passport.use(new JwtStrategy(jwtOptions, async (payload: { id: string }, done: any) => {
    try {
        // Find user by ID from the decoded JWT payload
        const user = await User.findById(payload.id);

        if (!user) {
            return done(null, false, { message: 'User not found' }); // No user found
        }
        
        // Return user object on successful authentication
        return done(null, user);
    } catch (err) {
        return done(err, false);
    }
}));

// Serialize user to store user ID in session (for local strategy)
passport.serializeUser((user, cb) => {
    cb(null, (user as userInterface).id);
});

// Deserialize user by ID (for local strategy)
passport.deserializeUser((id: string, cb: (err: any, user: Partial<userInterface> | null) => void) => {
    User.findById(id)
        .then(user => {
            if (user) {
                // Return only the properties you need (e.g., id, username, and isAdmin)
                cb(null, { id: user.id, username: user.username, isAdmin: user.isAdmin });
            } else {
                cb(null, null);
            }
        })
        .catch(err => {
            cb(err, null);
        });
});

export default passport;
