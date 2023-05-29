import express from "express";
import passport from "passport";
import prisma from "./Utils/Database/Database.js";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import bodyParser from "body-parser";
import { loginIndexRoute } from "./routes/login/login.js";
import { getUserList } from "./routes/get-user-list/getUserList.js";
import { getUserDetails } from "./routes/get-user-details/getUserDetails.js";
import { homeRoute } from "./routes/home/home.js";
import { updateUser } from "./routes/update-user/updateUser.js";
import { getRoles } from "./routes/get-roles/getRoles.js";
import { addRole } from "./routes/add-role/addRole.js";
import { addUser } from "./routes/add-user/addUser.js";

const app = express();
app.disable("x-powered-by");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
const port = process.env.PORT || 3000;
const secretKey = process.env.SECRET_KEY;
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: secretKey,
};

passport.use(
  new JwtStrategy(jwtOptions, (payload, done) => {
    // Handle the case when the user is a superadmin
    if (payload.isSuperAdmin) {
      return done(null, {
        username: process.env.SUPER_USER,
        roles: [
          {
            name: "superadmin",
          },
        ],
      });
    }

    // Fetch the user from the database based on the payload
    prisma.user
      .findUnique({
        where: { id: payload.id },
        select: {
          username: true,
          roles: {
            select: {
              name: true,
            },
          },
          id: true,
          email: true,
          createdAt: true,
          updatedAt: true,
        },
      })
      .then((user) => {
        if (user) {
          done(null, user);
        } else {
          done(null, false);
        }
      })
      .catch((err) => done(err, false));
  })
);

/**
 * @param {String} username
 * @param {String} password
 * @returns {object} object with the JWT as parameter of 'token'
 */
app.post("/login/", loginIndexRoute);

/**
 * @returns {Array} the list of 25 users on the page parameter
 * @param {Number} page
 */
app.get(
  "/get-user-list/(:page)?",
  passport.authenticate("jwt", { session: false }),
  getUserList
);

/**
 * @returns {object} the user object for the given id
 * @param {String} id
 */
app.get(
  "/get-user-details/(:id)?",
  passport.authenticate("jwt", { session: false }),
  getUserDetails
);

/**
 * @returns {object} the user object of the current authenticated user
 */
app.get("/home/", passport.authenticate("jwt", { session: false }), homeRoute);

/**
 * @returns {object} with the 'message' parameter depending on the succession
 * @param {String} id
 * @param {String} username
 * @param {String} password
 * @param {String} email
 * @param {Array} roles
 */
app.post(
  "/update-user/",
  passport.authenticate("jwt", { session: false }),
  updateUser
);

/**
 * @returns {Array} with the list of all roles
 */
app.post(
  "/get-roles/",
  passport.authenticate("jwt", { session: false }),
  getRoles
);

/**
 * @returns {object} with the 'message' parameter depending on the succession
 * @param {String} name
 */
app.post(
  "/add-role/",
  passport.authenticate("jwt", { session: false }),
  addRole
);

/**
 * @returns {object} with the 'message' parameter depending on the succession
 * @param {String} username
 * @param {String} password
 * @param {String} email
 * @param {Array} roles
 */
app.post(
  "/add-user/",
  passport.authenticate("jwt", { session: false }),
  addUser
);

app.listen(port, () => {
  console.log(`Express server listening on port ${port}`);
});
