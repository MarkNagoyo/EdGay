const express = require("express");
const passport = require("passport");
const prisma = require("./Utils/Database/Database");
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");

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

app.post("/login/", async (req, res) => {
  const { username, password } = req.body ?? {};

  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username or Password cant be empty" });
  }

  if (
    username === process.env.SUPER_USER &&
    password === process.env.SUPER_PASSWORD
  ) {
    const payload = { isSuperAdmin: true };
    const token = jwt.sign(payload, secretKey);
    return res.json({ token });
  }

  const userFromDatabase = await prisma.user.findUnique({
    where: {
      username: username,
    },
    select: { id: true, password: true, roles: true },
  });

  if (!userFromDatabase) {
    return res.status(400).json({ message: "Username is incorrect" });
  }

  if (userFromDatabase.password != password) {
    return res.status(400).json({ message: "Password is incorrect" });
  }

  const payload = { id: userFromDatabase.id };
  const token = jwt.sign(payload, secretKey);
  res.json({ token });
});

app.get(
  "/get-user-list/(:page)?",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    const page = req.params.page ?? 0;
    const usersPerPage = 25;

    if (req.user.username !== process.env.SUPER_USER) {
      return res.status(401);
    }

    const users = await prisma.user.findMany({
      take: usersPerPage,
      skip: usersPerPage * page,
      select: {
        id: true,
        username: true,
        email: true,
        roles: true,
      },
    });

    res.json({ users: users });
  }
);

app.get(
  "/get-user-details/(:id)?",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    const { id } = req.params;

    if (req.user.username !== process.env.SUPER_USER) {
      return res.status(401);
    }

    const user = await prisma.user.findUnique({
      where: { id: id },
      select: {
        username: true,
        email: true,
        roles: true,
      },
    });

    res.json({ user: user });
  }
);

app.get(
  "/home/",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    return res.json({ user: req.user });
  }
);

app.post(
  "/update-user/",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    const { id, username, password, email, roles } = req.body ?? {};

    if (req.user.username !== process.env.SUPER_USER) {
      return res.status(401);
    }

    if (!id) {
      return res.status(400).json({ message: "Parameter 'id' cant be empty" });
    }

    if (!username) {
      return res.status(400).json({ message: "Username cant be empty" });
    }

    if (!password) {
      return res.status(400).json({ message: "Password cant be empty" });
    }

    if (!email) {
      return res.status(400).json({ message: "Email cant be empty" });
    }

    const existingRoles = await prisma.roles.findMany({
      where: {
        name: {
          in: roles,
        },
      },
    });

    const roleIds = existingRoles.map((role) => role.id);

    await prisma.user.update({
      where: {
        id: id,
      },
      data: {
        username,
        password,
        email,
        roles: {
          connect: roleIds.length > 0 ? roleIds.map((id) => ({ id })) : [],
        },
      },
    });

    res.json({ message: "User updated successfully." });
  }
);

app.post(
  "/get-roles/",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    if (req.user.username !== process.env.SUPER_USER) {
      return res.status(401);
    }

    const roles = await prisma.roles.findMany({
      select: { id: true, name: true },
    });

    return res.json({ roles: roles });
  }
);

app.post(
  "/add-role/",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    const { name } = req.body ?? {};

    if (req.user.username !== process.env.SUPER_USER) {
      return res.status(401);
    }

    if (!name) {
      return res
        .status(400)
        .json({ message: "Name of the role cant be empty" });
    }

    const roleExists = await prisma.roles.findUnique({
      where: { name: name },
      select: { id: true },
    });

    if (roleExists) {
      return res.status(400).json({ message: "Role already exists" });
    }

    await prisma.roles.create({
      data: {
        name: name,
      },
    });

    res.json({ message: `${name} role created successfully.` });
  }
);

app.post(
  "/add-user/",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    const { username, password, email, roles } = req.body ?? {};

    if (req.user.username !== process.env.SUPER_USER) {
      return res.status(401);
    }

    if (!username) {
      return res.status(400).json({ message: "Username cant be empty" });
    }

    if (!password) {
      return res.status(400).json({ message: "Password cant be empty" });
    }

    if (!email) {
      return res.status(400).json({ message: "Email cant be empty" });
    }

    const userExists = await prisma.user.findUnique({
      where: { username: username },
      select: { id: true },
    });

    if (userExists || username === process.env.SUPER_USER) {
      return res.status(400).json({ message: "User already exists" });
    }

    const existingRoles = await prisma.roles.findMany({
      where: {
        name: {
          in: roles,
        },
      },
    });

    const roleIds = existingRoles.map((role) => role.id);

    await prisma.user.create({
      data: {
        username,
        password,
        email,
        roles: {
          connect: roleIds.length > 0 ? roleIds.map((id) => ({ id })) : [],
        },
      },
    });

    return res.json({ message: "User created" });
  }
);

app.listen(port, () => {
  console.log(`Express server listening on port ${port}`);
});
