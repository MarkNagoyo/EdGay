export const homeRoute = async (req, res) => {
  res.json({ user: req.user });
};
