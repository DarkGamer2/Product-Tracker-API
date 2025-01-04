import passport from "passport";
import { userInterface } from "../interfaces/interface";
import User from "../models/User";
import bcrypt from "bcryptjs";
const localStrategy =require("passport-local").Strategy;

module.exports = function(passport: any) {
    passport.use(new localStrategy(async (username: string, password: string, done: any) => {
        try {
            const user = await User.findOne({ username: username });

            if (!user || !user.password) { // Check if user or password is undefined
                return done(null, false);
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                return done(null, user);
            } else {
                return done(null, false);
            }
        } catch (err) {
            return done(err);
        }
    }));
}



passport.serializeUser((user,cb)=>{
    cb(null,(user as any).id);
})

passport.deserializeUser((id: string, cb: (err: any, user: Partial<userInterface> | null) => void) => {
    User.findById(id)
        .then(user => {
            if (user) {
                cb(null, { id: user.id, username: user.username, isAdmin: user.isAdmin });
            } else {
                cb(null, null);
            }
        })
        .catch(err => {
            cb(err, null);
        });
});
