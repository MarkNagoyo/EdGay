import prisma from "../../Utils/Database/Database.js";

export const getRoles = async (req, res) => {
  // Only allow accessing roles for superadmins
  if (req.user.username !== process.env.SUPER_USER) {
    return res.sendStatus(401);
  }

  const roles = await prisma.roles.findMany({
    select: { id: true, name: true },
  });

  return res.json({ roles });
};
