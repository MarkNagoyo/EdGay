import prisma from "../../Utils/Database/Database.js";
import bcrypt from "bcryptjs";

export const addUser = async (req, res) => {
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
        in: roles ?? [],
      },
    },
    select: {
      id: true,
    },
  });

  await prisma.user.create({
    data: {
      username,
      password: await bcrypt.hash(password, 10),
      email,
      roles: {
        connect: existingRoles,
      },
    },
  });

  return res.json({ message: "User created" });
};
