import prisma from "../../Utils/Database/Database.js";

export const getUserList = async (req, res) => {
  const page = req.params.page || 0;
  const usersPerPage = 25;

  // Only allow access to the user list for superadmins
  if (req.user.username !== process.env.SUPER_USER) {
    return res.sendStatus(401);
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

  res.json({ users });
};
