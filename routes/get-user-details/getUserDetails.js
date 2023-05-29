import prisma from "../../Utils/Database/Database.js";

export const getUserDetails = async (req, res) => {
  const { id } = req.params;

  // Only allow access to user details for superadmins
  if (req.user.username !== process.env.SUPER_USER) {
    return res.sendStatus(401);
  }

  const user = await prisma.user.findUnique({
    where: { id: id },
    select: {
      username: true,
      email: true,
      roles: true,
    },
  });

  res.json({ user });
};
