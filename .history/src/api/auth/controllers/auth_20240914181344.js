// In /api/auth/controllers/auth.js
module.exports = {
  async login(ctx) {
    const { identifier, password } = ctx.request.body;

    // Authenticate user
    const { jwt, user } = await strapi.plugins['users-permissions'].services.user.login({ identifier, password });

    // Set cookie with JWT token
    ctx.cookies.set('jwt', jwt, {
      httpOnly: true, // Prevent JavaScript access
      secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
      maxAge: 24 * 60 * 60 * 1000 // 1 day
    });

    // Return user data without JWT
    ctx.send({ user, jwt });
  },

  async register(ctx) {
    // Registration logic
    const { username, email, password } = ctx.request.body;

    // Create user and generate JWT token
    const { jwt, user } = await strapi.plugins['users-permissions'].services.user.add({
      username,
      email,
      password
    });

    // Set cookie with JWT token
    ctx.cookies.set('jwt', jwt, {
      httpOnly: true, // Prevent JavaScript access
      secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
      maxAge: 24 * 60 * 60 * 1000 // 1 day
    });

    // Return user data without JWT
    ctx.send({ user, jwt });
  }
};
