export const isLogin = async (req, res, next) => {
  try {
    if (req.session.user) {
      next(); // Call next middleware
      return; // Terminate the middleware function
    } else {
      res.redirect("/users/signin"); // Redirect if user is not logged in
    }
  } catch (err) {
    console.log("isLogin", err);
  }
};

export const isLogout = async (req, res, next) => {
  try {
    if (req.session.user) {
      res.redirect("/"); // Redirect if user is logged in
    } else {
      next(); // Call next middleware if user is not logged in
    }
  } catch (err) {
    console.log("isLogout", err);
  }
};