// import { hash } from "bcryptjs";
import prisma from "../../Utils/Database/Database.js";
import bcrypt from "bcryptjs";

export const updateUser = async (req, res) => {
  const { id, username, password, email, roles } = req.body || {};

  // Only allow updating users for superadmins
  if (req.user.username !== process.env.SUPER_USER) {
    return res.sendStatus(401);
  }

  // Validate parameters
  if (!id) {
    return res.status(400).json({ message: "Parameter 'id' cannot be empty" });
  }

  if (!username) {
    return res.status(400).json({ message: "Username cannot be empty" });
  }

  if (!password) {
    return res.status(400).json({ message: "Password cannot be empty" });
  }

  if (!email) {
    return res.status(400).json({ message: "Email cannot be empty" });
  }

  // Fetch existing roles based on provided role names
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

  // Update the user
  await prisma.user.update({
    where: {
      id: id,
    },
    data: {
      username,
      password: await bcrypt.hash(password, 10),
      email,
      roles: {
        set: [],
        connect: existingRoles,
      },
    },
  });

  res.json({ message: "User updated successfully" });
};
