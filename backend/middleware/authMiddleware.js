/**
 * middleware/authMiddleware.js — Session Authentication & Authorization Guards
 */

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({
      error: 'Authentication required. Please sign in.',
      code: 'UNAUTHENTICATED',
    });
  }
  next();
}

function checkOwnership(getOwnerId) {
  return (req, res, next) => {
    const ownerId = typeof getOwnerId === 'function' ? getOwnerId(req) : req.params[getOwnerId];
    if (req.session.userId !== ownerId) {
      return res.status(403).json({
        error: 'Forbidden. You do not have permission to access this resource.',
        code: 'FORBIDDEN',
      });
    }
    next();
  };
}

module.exports = {
  requireAuth,
  checkOwnership,
};
