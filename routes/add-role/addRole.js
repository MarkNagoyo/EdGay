import prisma from "../../Utils/Database/Database.js";

export const addRole = async (req, res) => {
  const { name } = req.body || {};

  // Only allow adding roles for superadmins
  if (req.user.username !== process.env.SUPER_USER) {
    return res.sendStatus(401);
  }

  // Validate role name
  if (!name) {
    return res
      .status(400)
      .json({ message: "Name of the role cannot be empty" });
  }

  // Check if role already exists
  const roleExists = await prisma.roles.findUnique({
    where: { name: name },
    select: { id: true },
  });

  if (roleExists) {
    return res.status(400).json({ message: "Role already exists" });
  }

  // Create the role
  await prisma.roles.create({
    data: {
      name: name,
    },
  });

  res.json({ message: `${name} role created successfully` });
};
