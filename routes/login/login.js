import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import prisma from "../../Utils/Database/Database.js";

const secretKey = process.env.SECRET_KEY;

export const loginIndexRoute = async (req, res) => {
  const { username, password } = req.body || {};

  // Validate username and password
  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username or Password cannot be empty" });
  }

  // Check if the user is a superadmin
  if (
    username === process.env.SUPER_USER &&
    password === process.env.SUPER_PASSWORD
  ) {
    const payload = { isSuperAdmin: true };
    const token = jwt.sign(payload, secretKey);
    return res.json({ token });
  }

  // Check if the user exists and verify the password
  const userFromDatabase = await prisma.user.findUnique({
    where: { username: username },
    select: { id: true, password: true, roles: true },
  });

  if (!userFromDatabase) {
    return res.status(400).json({ message: "Username is incorrect" });
  }

  if (!(await bcrypt.compare(password, userFromDatabase.password))) {
    return res.status(400).json({ message: "Password is incorrect" });
  }

  const payload = { id: userFromDatabase.id };
  const token = jwt.sign(payload, secretKey);
  res.json({ token });
};
